function New-OspfSessionState {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [Parameter(Mandatory)][ipaddress]$LocalAddress,
        [int]$PrefixLength = 24,
        [ipaddress]$AreaId = '0.0.0.0',
        [ValidateSet('Broadcast', 'PointToPoint')][string]$NetworkType = 'Broadcast',
        [int]$HelloInterval = 10,
        [long]$DeadInterval = 40,
        [int]$Priority = 1,
        [int]$Cost = 10,
        [int]$Mtu = 1500,
        [int]$InterfaceMtu = 1500,
        [int]$Options = 2,
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1
    )
    $net = ConvertFrom-OspfPrefix "$LocalAddress/$PrefixLength"
    @{
        Name               = $Name
        RouterId           = $RouterId
        RouterIdLong       = ConvertTo-OspfLong $RouterId
        AreaId             = $AreaId
        LocalAddress       = $LocalAddress
        LocalAddressLong   = ConvertTo-OspfLong $LocalAddress
        PrefixLength       = $PrefixLength
        Mask               = $net.Mask
        NetworkLong        = $net.NetworkLong
        MaskLong           = $net.MaskLong
        NetworkType        = $NetworkType
        HelloInterval      = $HelloInterval
        DeadInterval       = $DeadInterval
        RxmtInterval       = 5
        Priority           = $Priority
        Cost               = $Cost
        Mtu                = $Mtu
        InterfaceMtu       = $InterfaceMtu
        Options            = $Options
        AuthType           = $AuthType
        AuthKey            = $AuthKey
        KeyId              = $KeyId
        CryptoSequence     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        InterfaceState     = 'Down'
        Dr                 = [long]0
        Bdr                = [long]0
        WaitDeadline       = [datetime]::MaxValue
        NextHello          = [datetime]::MinValue
        LastRefresh        = [datetime]::UtcNow
        Neighbors          = @{}
        Lsdb               = @{}
        Originated         = @{}
        SeqFloor           = @{}
        Prefixes           = [System.Collections.Generic.List[object]]::new()
        Externals          = [System.Collections.Generic.List[object]]::new()
        Summaries          = [System.Collections.Generic.List[object]]::new()
        Events             = [System.Collections.Generic.List[object]]::new()
        Outbox             = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        Lock               = [object]::new()
        Status             = 'Stopped'
        SuppressHellos     = $false
        CorruptChecksum    = $false
        LsaDirty           = $false
        Cancel             = $false
        HoldDown           = @{}
        Socket             = $null
        Runspace           = $null
        PowerShell         = $null
        Handle             = $null
        Created            = [datetime]::UtcNow
    }
}

function Invoke-OspfLock {
    param($Session, [scriptblock]$ScriptBlock)
    [System.Threading.Monitor]::Enter($Session.Lock)
    try { & $ScriptBlock }
    finally { [System.Threading.Monitor]::Exit($Session.Lock) }
}

function Add-OspfEvent {
    param($Session, [string]$Direction, [string]$Type, [string]$Message, $Neighbor = $null, [byte[]]$Bytes = $null)
    $Session.Events.Add([pscustomobject]@{
            PSTypeName = 'PowerOSPF.Event'
            Time       = [datetime]::UtcNow
            Direction  = $Direction
            Type       = $Type
            Neighbor   = $Neighbor
            Message    = $Message
            Bytes      = $Bytes
        })
    while ($Session.Events.Count -gt 500) { $Session.Events.RemoveAt(0) }
}

function Send-OspfPacket {
    param($Session, [int]$Type, [byte[]]$Body, [ipaddress]$Destination, [string]$Info = '', $Neighbor = $null)
    $Session.CryptoSequence++
    $pkt = New-OspfPacketBytes -Type $Type -RouterId $Session.RouterId -AreaId $Session.AreaId -Body $Body -AuthType $Session.AuthType `
        -AuthKey $Session.AuthKey -KeyId $Session.KeyId -CryptoSequence $Session.CryptoSequence -CorruptChecksum:([bool]$Session.CorruptChecksum)
    $Session.Outbox.Enqueue([pscustomobject]@{ Destination = $Destination; Bytes = $pkt })
    Add-OspfEvent -Session $Session -Direction 'Sent' -Type $script:PacketTypeNames[$Type] -Message "$Info to $Destination" -Neighbor $Neighbor -Bytes $pkt
}

function Send-OspfHello {
    param($Session)
    $n = [long[]]@($Session.Neighbors.Values | ForEach-Object { $_.RouterIdLong })
    $body = Get-OspfHelloBody -Mask $Session.Mask -HelloInterval $Session.HelloInterval -Options $Session.Options -Priority $Session.Priority `
        -DeadInterval $Session.DeadInterval -Dr $Session.Dr -Bdr $Session.Bdr -Neighbors $n
    Send-OspfPacket -Session $Session -Type 1 -Body $body -Destination $script:AllSpfRouters -Info "neighbors=$($n.Count)"
}

function Get-OspfLsaAge {
    param($Entry, [datetime]$Now)
    [int][math]::Min($script:OspfMaxAge, $Entry.Age0 + [math]::Floor(($Now - $Entry.InstallTime).TotalSeconds))
}

function Get-OspfEntryBytes {
    param($Entry, [datetime]$Now, [int]$AddAge = 0)
    $b = [byte[]]$Entry.Bytes.Clone()
    $age = [math]::Min($script:OspfMaxAge, (Get-OspfLsaAge $Entry $Now) + $AddAge)
    $b[0] = [byte]($age -shr 8)
    $b[1] = [byte]($age -band 0xFF)
    , $b
}

function Get-OspfEntryHeader {
    param($Entry, [datetime]$Now)
    Read-OspfLsaHeader -Data ([byte[]](Get-OspfEntryBytes $Entry $Now)) -Offset 0
}

function Install-OspfLsa {
    param($Session, [byte[]]$Lsa, [datetime]$Now, [switch]$Originated)
    $h = Read-OspfLsaHeader $Lsa 0
    $Session.Lsdb[$h.Key] = @{ Key = $h.Key; Bytes = $Lsa; Age0 = $h.Age; InstallTime = $Now; Originated = [bool]$Originated }
    $h.Key
}

function Set-OspfNeighborState {
    param($Session, $Neighbor, [string]$State, [string]$Reason, [datetime]$Now)
    $old = $Neighbor.State
    if ($old -eq $State) { return }
    $Neighbor.State = $State
    Add-OspfEvent -Session $Session -Direction 'Info' -Type 'NeighborState' -Neighbor $Neighbor.RouterId.ToString() -Message "$old -> $State ($Reason)"
    if ($script:NeighborRank[$State] -lt $script:NeighborRank['ExStart']) {
        $Neighbor.RequestList = @{}
        $Neighbor.Retrans = @{}
        $Neighbor.DbSummary = [System.Collections.Generic.List[string]]::new()
        $Neighbor.LastDbdBody = $null
        $Neighbor.LastRecv = $null
    }
    if ($old -eq 'Full' -or $State -eq 'Full') { $Session.LsaDirty = $true }
}

function New-OspfNeighbor {
    param([long]$RouterIdLong, [long]$Address, [datetime]$Now)
    @{
        RouterId     = ConvertFrom-OspfLong $RouterIdLong
        RouterIdLong = $RouterIdLong
        Address      = $Address
        State        = 'Down'
        Priority     = 0
        Dr           = [long]0
        Bdr          = [long]0
        Options      = 0
        Deadline     = $Now
        DdSeq        = [long]0
        IsMaster     = $false
        RequestList  = @{}
        Retrans      = @{}
        DbSummary    = [System.Collections.Generic.List[string]]::new()
        LastDbdBody  = $null
        LastDbdMore  = $false
        LastDbdTime  = $Now
        LastLsrTime  = $Now
        LastRecv     = $null
        LastCrypto   = [long]-1
        Since        = $Now
    }
}

function Select-OspfDesignatedRouter {
    param($Candidates)
    $pick = {
        param($list)
        @($list | Sort-Object -Property @{ Expression = { $_.Priority }; Descending = $true }, @{ Expression = { $_.Id }; Descending = $true }) | Select-Object -First 1
    }
    $bdrPool = @($Candidates | Where-Object { $_.Dr -ne $_.Ip })
    $declBdr = @($bdrPool | Where-Object { $_.Bdr -eq $_.Ip })
    $b = if ($declBdr.Count) { & $pick $declBdr } else { & $pick $bdrPool }
    $drPool = @($Candidates | Where-Object { $_.Dr -eq $_.Ip })
    $d = if ($drPool.Count) { & $pick $drPool } else { $b }
    [pscustomobject]@{ Dr = $(if ($d) { [long]$d.Ip } else { [long]0 }); Bdr = $(if ($b) { [long]$b.Ip } else { [long]0 }) }
}

function Invoke-OspfElection {
    param($Session, [datetime]$Now)
    if ($Session.NetworkType -ne 'Broadcast') { Update-OspfAdjacencies -Session $Session -Now $Now; return }
    $others = @($Session.Neighbors.Values | Where-Object { $script:NeighborRank[$_.State] -ge 2 -and $_.Priority -gt 0 } |
            ForEach-Object { [pscustomobject]@{ Id = $_.RouterIdLong; Ip = $_.Address; Priority = $_.Priority; Dr = $_.Dr; Bdr = $_.Bdr } })
    $self = [pscustomobject]@{ Id = $Session.RouterIdLong; Ip = $Session.LocalAddressLong; Priority = $Session.Priority; Dr = $Session.Dr; Bdr = $Session.Bdr }
    $oldDr = $Session.Dr; $oldBdr = $Session.Bdr
    $result = $null
    for ($pass = 0; $pass -lt 2; $pass++) {
        $cands = @($others)
        if ($Session.Priority -gt 0) { $cands += $self }
        $result = Select-OspfDesignatedRouter $cands
        $changed = (($result.Dr -eq $self.Ip) -ne ($self.Dr -eq $self.Ip)) -or (($result.Bdr -eq $self.Ip) -ne ($self.Bdr -eq $self.Ip))
        if (-not $changed) { break }
        $self.Dr = $result.Dr; $self.Bdr = $result.Bdr
    }
    $Session.Dr = $result.Dr
    $Session.Bdr = $result.Bdr
    $Session.InterfaceState = if ($Session.Dr -eq $Session.LocalAddressLong) { 'DR' } elseif ($Session.Bdr -eq $Session.LocalAddressLong) { 'BDR' } else { 'DROther' }
    $Session.WaitDeadline = [datetime]::MaxValue
    if ($oldDr -ne $Session.Dr -or $oldBdr -ne $Session.Bdr) {
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Election' -Message "DR=$(ConvertFrom-OspfLong $Session.Dr) BDR=$(ConvertFrom-OspfLong $Session.Bdr) state=$($Session.InterfaceState)"
        $Session.NextHello = $Now
        $Session.LsaDirty = $true
    }
    Update-OspfAdjacencies -Session $Session -Now $Now
}

function Test-OspfAdjacencyNeeded {
    param($Session, $Neighbor)
    if ($Session.NetworkType -eq 'PointToPoint') { return $true }
    $me = $Session.LocalAddressLong
    ($Session.Dr -eq $me -or $Session.Bdr -eq $me -or $Neighbor.Address -eq $Session.Dr -or $Neighbor.Address -eq $Session.Bdr)
}

function Update-OspfAdjacencies {
    param($Session, [datetime]$Now)
    foreach ($n in @($Session.Neighbors.Values)) {
        $rank = $script:NeighborRank[$n.State]
        $need = Test-OspfAdjacencyNeeded $Session $n
        if ($n.State -eq '2-Way' -and $need) { Start-OspfAdjacency $Session $n $Now }
        elseif ($rank -ge 3 -and -not $need) { Set-OspfNeighborState $Session $n '2-Way' 'AdjOK? no adjacency needed' $Now }
    }
}

function Start-OspfAdjacency {
    param($Session, $Neighbor, [datetime]$Now)
    Set-OspfNeighborState $Session $Neighbor 'ExStart' 'AdjOK?' $Now
    $Neighbor.IsMaster = $true
    $Neighbor.DdSeq = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -band 0x7FFFFFFF)
    $Neighbor.RequestList = @{}
    $Neighbor.Retrans = @{}
    $Neighbor.LastRecv = $null
    $Neighbor.DbSummary = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $Session.Lsdb.Values) {
        if ((Get-OspfLsaAge $e $Now) -lt $script:OspfMaxAge) { $Neighbor.DbSummary.Add($e.Key) }
    }
    Send-OspfInitialDbd $Session $Neighbor $Now
}

function Send-OspfDbdPacket {
    param($Session, $Neighbor, [byte[]]$Body, [datetime]$Now, [string]$Info)
    $Neighbor.LastDbdBody = $Body
    $Neighbor.LastDbdTime = $Now
    Send-OspfPacket -Session $Session -Type 2 -Body $Body -Destination (ConvertFrom-OspfLong $Neighbor.Address) -Info $Info -Neighbor $Neighbor.RouterId.ToString()
}

function Send-OspfInitialDbd {
    param($Session, $Neighbor, [datetime]$Now)
    $body = Get-OspfDbdBody -InterfaceMtu $Session.Mtu -Options $Session.Options -Flags 7 -Sequence $Neighbor.DdSeq
    $Neighbor.LastDbdMore = $true
    Send-OspfDbdPacket $Session $Neighbor $body $Now "init seq=$($Neighbor.DdSeq)"
}

function Send-OspfDbdChunk {
    param($Session, $Neighbor, [datetime]$Now)
    $limit = [math]::Max(1, [int][math]::Floor(($Session.InterfaceMtu - 52) / 20))
    $headers = [System.Collections.Generic.List[byte[]]]::new()
    while ($Neighbor.DbSummary.Count -gt 0 -and $headers.Count -lt $limit) {
        $key = $Neighbor.DbSummary[0]
        $Neighbor.DbSummary.RemoveAt(0)
        $e = $Session.Lsdb[$key]
        if ($e) { $headers.Add([byte[]](Get-OspfEntryBytes $e $Now)[0..19]) }
    }
    $more = $Neighbor.DbSummary.Count -gt 0
    $flags = 0
    if ($more) { $flags = $flags -bor 2 }
    if ($Neighbor.IsMaster) { $flags = $flags -bor 1 }
    $Neighbor.LastDbdMore = $more
    $body = Get-OspfDbdBody -InterfaceMtu $Session.Mtu -Options $Session.Options -Flags $flags -Sequence $Neighbor.DdSeq -Headers $headers.ToArray()
    Send-OspfDbdPacket $Session $Neighbor $body $Now "seq=$($Neighbor.DdSeq) headers=$($headers.Count) more=$more"
}

function Send-OspfLsrTo {
    param($Session, $Neighbor, [datetime]$Now)
    if ($Neighbor.RequestList.Count -eq 0) { return }
    $reqs = @($Neighbor.RequestList.Values | Select-Object -First 50 | ForEach-Object {
            [pscustomobject]@{ Type = $_.Type; LinkStateId = $_.LinkStateId; AdvertisingRouter = $_.AdvertisingRouter } })
    $Neighbor.LastLsrTime = $Now
    Send-OspfPacket -Session $Session -Type 3 -Body (Get-OspfLsrBody -Requests $reqs) -Destination (ConvertFrom-OspfLong $Neighbor.Address) -Info "requests=$($reqs.Count)" -Neighbor $Neighbor.RouterId.ToString()
}

function Send-OspfLsuTo {
    param($Session, $Neighbor, $Lsas)
    $max = $Session.InterfaceMtu - 60
    $batch = [System.Collections.Generic.List[byte[]]]::new()
    $size = 0
    $flush = {
        if ($batch.Count -gt 0) {
            Send-OspfPacket -Session $Session -Type 4 -Body (Get-OspfLsuBody -Lsas $batch.ToArray()) -Destination (ConvertFrom-OspfLong $Neighbor.Address) -Info "lsas=$($batch.Count)" -Neighbor $Neighbor.RouterId.ToString()
            $batch.Clear()
        }
    }
    foreach ($l in (ConvertTo-OspfByteList $Lsas)) {
        if ($size + $l.Length -gt $max -and $batch.Count -gt 0) { & $flush; $size = 0 }
        $batch.Add($l)
        $size += $l.Length
    }
    & $flush
}

function Send-OspfAck {
    param($Session, $Neighbor, $Headers)
    $h = ConvertTo-OspfByteList $Headers
    if ($h.Count -eq 0) { return }
    Send-OspfPacket -Session $Session -Type 5 -Body (Get-OspfLsAckBody -Headers $h) -Destination (ConvertFrom-OspfLong $Neighbor.Address) -Info "acks=$($h.Count)" -Neighbor $Neighbor.RouterId.ToString()
}

function Send-OspfFlood {
    param($Session, [string[]]$Keys, [datetime]$Now, $Except = $null)
    foreach ($n in @($Session.Neighbors.Values)) {
        if ($script:NeighborRank[$n.State] -lt $script:NeighborRank['Exchange']) { continue }
        if ($null -ne $Except -and $n.RouterIdLong -eq $Except.RouterIdLong) { continue }
        $lsas = [System.Collections.Generic.List[byte[]]]::new()
        foreach ($k in $Keys) {
            $e = $Session.Lsdb[$k]
            if ($e) {
                $h = Read-OspfLsaHeader $e.Bytes 0
                $n.Retrans[$k] = @{ Sequence = $h.Sequence; Time = $Now }
                $lsas.Add([byte[]](Get-OspfEntryBytes $e $Now 1))
            }
        }
        if ($lsas.Count -gt 0) { Send-OspfLsuTo $Session $n $lsas.ToArray() }
    }
}

function Restart-OspfAdjacency {
    param($Session, $Neighbor, [string]$Reason, [datetime]$Now)
    Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Adjacency' -Neighbor $Neighbor.RouterId.ToString() -Message $Reason
    Set-OspfNeighborState $Session $Neighbor '2-Way' $Reason $Now
    if (Test-OspfAdjacencyNeeded $Session $Neighbor) { Start-OspfAdjacency $Session $Neighbor $Now }
}

function Complete-OspfExchange {
    param($Session, $Neighbor, [datetime]$Now)
    if ($Neighbor.RequestList.Count -eq 0) {
        Set-OspfNeighborState $Session $Neighbor 'Full' 'ExchangeDone' $Now
    }
    else {
        Set-OspfNeighborState $Session $Neighbor 'Loading' 'ExchangeDone' $Now
        Send-OspfLsrTo $Session $Neighbor $Now
    }
}
