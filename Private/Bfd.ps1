$script:BfdSessions = @{}
$script:BfdStateNames = @{ 0 = 'AdminDown'; 1 = 'Down'; 2 = 'Init'; 3 = 'Up' }
$script:BfdStateNumbers = @{ AdminDown = 0; Down = 1; Init = 2; Up = 3 }
$script:BfdAuthNumbers = @{ None = 0; Simple = 1; KeyedMd5 = 2; MeticulousKeyedMd5 = 3; KeyedSha1 = 4; MeticulousKeyedSha1 = 5 }
$script:BfdAuthNames = @{ 0 = 'None'; 1 = 'Simple'; 2 = 'KeyedMd5'; 3 = 'MeticulousKeyedMd5'; 4 = 'KeyedSha1'; 5 = 'MeticulousKeyedSha1' }

function Get-BfdDigest {
    param([byte[]]$Packet, [int]$AuthType, [string]$Key)
    $size = if ($AuthType -in 2, 3) { 16 } else { 20 }
    $k = [byte[]]::new($size)
    $kb = [System.Text.Encoding]::ASCII.GetBytes($Key)
    for ($i = 0; $i -lt $size -and $i -lt $kb.Length; $i++) { $k[$i] = $kb[$i] }
    $work = [byte[]]$Packet.Clone()
    for ($i = 0; $i -lt $size; $i++) { $work[32 + $i] = $k[$i] }
    if ($size -eq 16) { , [byte[]][System.Security.Cryptography.MD5]::HashData($work) }
    else { , [byte[]][System.Security.Cryptography.SHA1]::HashData($work) }
}

function New-BfdPacketBytes {
    param(
        [int]$State = 1, [int]$Diagnostic = 0, [int]$DetectMult = 3,
        [long]$MyDiscriminator = 1, [long]$YourDiscriminator = 0,
        [long]$DesiredMinTx = 1000000, [long]$RequiredMinRx = 1000000, [long]$RequiredMinEchoRx = 0,
        [bool]$Poll = $false, [bool]$Final = $false, [bool]$ControlPlaneIndependent = $false, [bool]$Demand = $false, [bool]$Multipoint = $false,
        [string]$AuthType = 'None', [string]$AuthKey = '', [int]$KeyId = 1, [long]$Sequence = 0
    )
    $au = $script:BfdAuthNumbers[$AuthType]
    $flags = 0
    if ($Poll) { $flags = $flags -bor 0x20 }
    if ($Final) { $flags = $flags -bor 0x10 }
    if ($ControlPlaneIndependent) { $flags = $flags -bor 0x08 }
    if ($au -ne 0) { $flags = $flags -bor 0x04 }
    if ($Demand) { $flags = $flags -bor 0x02 }
    if ($Multipoint) { $flags = $flags -bor 0x01 }
    $auth = [byte[]]@()
    switch ($au) {
        1 {
            $pw = [System.Text.Encoding]::ASCII.GetBytes($AuthKey)
            if ($pw.Length -lt 1 -or $pw.Length -gt 16) { throw 'BFD simple passwords are 1-16 characters' }
            $auth = [byte[]](Join-OspfBytes (ConvertTo-OspfBytes 1 1) (ConvertTo-OspfBytes (3 + $pw.Length) 1) (ConvertTo-OspfBytes $KeyId 1) $pw)
        }
        { $_ -in 2, 3 } { $auth = [byte[]](Join-OspfBytes (ConvertTo-OspfBytes $au 1) (ConvertTo-OspfBytes 24 1) (ConvertTo-OspfBytes $KeyId 1) (ConvertTo-OspfBytes 0 1) (ConvertTo-OspfBytes $Sequence 4) ([byte[]]::new(16))) }
        { $_ -in 4, 5 } { $auth = [byte[]](Join-OspfBytes (ConvertTo-OspfBytes $au 1) (ConvertTo-OspfBytes 28 1) (ConvertTo-OspfBytes $KeyId 1) (ConvertTo-OspfBytes 0 1) (ConvertTo-OspfBytes $Sequence 4) ([byte[]]::new(20))) }
    }
    $len = 24 + $auth.Length
    $pkt = [byte[]](Join-OspfBytes (ConvertTo-OspfBytes ((1 -shl 5) -bor $Diagnostic) 1) (ConvertTo-OspfBytes (($State -shl 6) -bor $flags) 1) (ConvertTo-OspfBytes $DetectMult 1) (ConvertTo-OspfBytes $len 1) `
            (ConvertTo-OspfBytes $MyDiscriminator 4) (ConvertTo-OspfBytes $YourDiscriminator 4) (ConvertTo-OspfBytes $DesiredMinTx 4) (ConvertTo-OspfBytes $RequiredMinRx 4) (ConvertTo-OspfBytes $RequiredMinEchoRx 4) $auth)
    if ($au -ge 2) {
        $d = Get-BfdDigest -Packet $pkt -AuthType $au -Key $AuthKey
        for ($i = 0; $i -lt $d.Length; $i++) { $pkt[32 + $i] = $d[$i] }
    }
    , $pkt
}

function Test-BfdAuth {
    param([byte[]]$Data, [string]$AuthKey)
    if (($Data[1] -band 0x04) -eq 0 -or $Data.Length -lt 26) { return $false }
    $au = [int]$Data[24]
    switch ($au) {
        1 { $pw = [System.Text.Encoding]::ASCII.GetBytes($AuthKey); return ([System.Convert]::ToHexString($pw) -eq [System.Convert]::ToHexString([byte[]]$Data[27..($Data.Length - 1)])) }
        { $_ -in 2, 3, 4, 5 } {
            $size = if ($au -in 2, 3) { 16 } else { 20 }
            if ($Data.Length -lt 32 + $size) { return $false }
            $d = Get-BfdDigest -Packet $Data -AuthType $au -Key $AuthKey
            return ([System.Convert]::ToHexString($d) -eq [System.Convert]::ToHexString([byte[]]$Data[32..(31 + $size)]))
        }
        default { return $false }
    }
}

function New-BfdSessionState {
    param([string]$Name, [ipaddress]$Peer, [ipaddress]$LocalAddress, [int]$DetectMult, [long]$DesiredMinTx, [long]$RequiredMinRx, [string]$AuthType, [string]$AuthKey, [int]$KeyId)
    @{
        Name = $Name; Peer = $Peer; LocalAddress = $LocalAddress; State = 'Down'; Diagnostic = 0
        MyDisc = [long](Get-Random -Minimum 1 -Maximum 2147483647); YourDisc = [long]0
        DetectMult = $DetectMult; DesiredMinTx = $DesiredMinTx; RequiredMinRx = $RequiredMinRx
        RemoteState = 'Down'; RemoteDetectMult = 3; RemoteDesiredMinTx = [long]1000000; RemoteRequiredMinRx = [long]1000000
        AuthType = $AuthType; AuthKey = $AuthKey; KeyId = $KeyId; AuthSeq = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()); RemoteAuthSeq = [long]-1
        NextTx = [datetime]::MinValue; DetectDeadline = [datetime]::MaxValue; WasUp = $false; PollPending = $false; FinalPending = $false
        SuppressTx = $false; Status = 'Stopped'; Cancel = $false
        Events = [System.Collections.Generic.List[object]]::new()
        Outbox = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        Lock = [object]::new(); Socket = $null; RxSocket = $null; Runspace = $null; PowerShell = $null; Handle = $null
    }
}

function Set-BfdState {
    param($S, [string]$State, [int]$Diag, [string]$Reason)
    if ($S.State -eq $State) { return }
    Add-OspfEvent -Session $S -Direction 'Info' -Type 'BfdState' -Message "$($S.State) -> $State ($Reason)"
    $S.State = $State
    $S.Diagnostic = $Diag
    if ($State -eq 'Up') { $S.WasUp = $true }
    if ($State -eq 'Down' -or $State -eq 'AdminDown') { $S.YourDisc = if ($State -eq 'AdminDown') { $S.YourDisc } else { [long]0 } }
}

function Get-BfdTxInterval {
    param($S)
    if ($S.State -eq 'Up') { [long][math]::Max($S.DesiredMinTx, $S.RemoteRequiredMinRx) } else { [long][math]::Max($S.DesiredMinTx, 1000000) }
}

function Send-BfdPacket {
    param($S, [datetime]$Now, [bool]$Final = $false)
    $S.AuthSeq++
    $desired = if ($S.State -eq 'Up') { $S.DesiredMinTx } else { [long][math]::Max($S.DesiredMinTx, 1000000) }
    $pkt = New-BfdPacketBytes -State $script:BfdStateNumbers[$S.State] -Diagnostic $S.Diagnostic -DetectMult $S.DetectMult -MyDiscriminator $S.MyDisc -YourDiscriminator $S.YourDisc `
        -DesiredMinTx $desired -RequiredMinRx $S.RequiredMinRx -Poll $S.PollPending -Final $Final -AuthType $S.AuthType -AuthKey $S.AuthKey -KeyId $S.KeyId -Sequence $S.AuthSeq
    $S.Outbox.Enqueue([pscustomobject]@{ Destination = $S.Peer; Bytes = $pkt })
    Add-OspfEvent -Session $S -Direction 'Sent' -Type 'BfdControl' -Message "state=$($S.State) to $($S.Peer)" -Bytes $pkt
}

function Invoke-BfdReceive {
    param($S, [byte[]]$Data, [ipaddress]$Source, [datetime]$Now = [datetime]::UtcNow)
    if ($S.Status -ne 'Running' -or -not $Source.Equals($S.Peer)) { return }
    $m = ConvertFrom-BfdControl -Packet $Data -AuthKey $S.AuthKey
    $drop = { param($why) Add-OspfEvent -Session $S -Direction 'Received' -Type 'BfdControl' -Message "Dropped: $why" -Bytes $Data }
    if (-not $m.Valid) { & $drop $m.Error; return }
    if ($m.Version -ne 1) { & $drop "version $($m.Version)"; return }
    if ($m.DetectMult -eq 0 -or $m.Multipoint -or $m.MyDiscriminator -eq 0) { & $drop 'invalid fields'; return }
    if ($m.YourDiscriminator -eq 0 -and $m.State -notin 'Down', 'AdminDown') { & $drop 'YourDiscriminator 0 in non-Down state'; return }
    if ($m.YourDiscriminator -ne 0 -and $m.YourDiscriminator -ne $S.MyDisc) { & $drop 'unknown YourDiscriminator'; return }
    if ($m.AuthType -ne $S.AuthType) { & $drop "auth type mismatch ($($m.AuthType))"; return }
    if ($S.AuthType -ne 'None') {
        if (-not $m.AuthValid) { & $drop 'authentication failed'; return }
        if ($S.AuthType -like 'Meticulous*') { if ($m.Sequence -le $S.RemoteAuthSeq) { & $drop 'sequence not increasing'; return } }
        elseif ($S.AuthType -like 'Keyed*' -and $S.RemoteAuthSeq -ge 0 -and $m.Sequence -lt $S.RemoteAuthSeq) { & $drop 'sequence went backwards'; return }
        $S.RemoteAuthSeq = $m.Sequence
    }
    Add-OspfEvent -Session $S -Direction 'Received' -Type 'BfdControl' -Message "state=$($m.State) from $Source" -Bytes $Data
    $S.YourDisc = $m.MyDiscriminator
    $S.RemoteState = $m.State
    $S.RemoteDetectMult = $m.DetectMult
    $S.RemoteDesiredMinTx = $m.DesiredMinTxInterval
    $S.RemoteRequiredMinRx = $m.RequiredMinRxInterval
    if ($m.Final) { $S.PollPending = $false }
    if ($S.State -ne 'AdminDown') {
        if ($m.State -eq 'AdminDown') {
            if ($S.State -ne 'Down') { Set-BfdState $S 'Down' 3 'neighbor signaled AdminDown' }
        }
        else {
            switch ($S.State) {
                'Down' { if ($m.State -eq 'Down') { Set-BfdState $S 'Init' 0 'remote Down' } elseif ($m.State -eq 'Init') { Set-BfdState $S 'Up' 0 'remote Init' } }
                'Init' { if ($m.State -in 'Init', 'Up') { Set-BfdState $S 'Up' 0 "remote $($m.State)" } }
                'Up' { if ($m.State -eq 'Down') { Set-BfdState $S 'Down' 3 'neighbor signaled Down' } }
            }
        }
    }
    $detect = [long]$S.RemoteDetectMult * [math]::Max($S.RequiredMinRx, $S.RemoteDesiredMinTx)
    $S.DetectDeadline = $Now.AddTicks($detect * 10)
    if ($m.Poll) { Send-BfdPacket $S $Now $true }
}

function Invoke-BfdTick {
    param($S, [datetime]$Now = [datetime]::UtcNow)
    if ($S.Status -ne 'Running') { return }
    if ($S.State -in 'Init', 'Up' -and $Now -gt $S.DetectDeadline) {
        Set-BfdState $S 'Down' 1 'control detection time expired'
        $S.DetectDeadline = [datetime]::MaxValue
    }
    if ($Now -ge $S.NextTx) {
        if (-not $S.SuppressTx) { Send-BfdPacket $S $Now }
        $interval = Get-BfdTxInterval $S
        $S.NextTx = $Now.AddTicks([long]($interval * 10 * (0.75 + 0.25 * (Get-Random -Minimum 0.0 -Maximum 1.0))))
    }
}

function Invoke-BfdRuntime {
    param($S)
    $buf = [byte[]]::new(2048)
    while (-not $S.Cancel) {
        try {
            if ($S.RxSocket.Poll(20000, [System.Net.Sockets.SelectMode]::SelectRead)) {
                $ep = [System.Net.EndPoint][System.Net.IPEndPoint]::new([ipaddress]::Any, 0)
                $n = $S.RxSocket.ReceiveFrom($buf, [ref]$ep)
                $data = [byte[]]$buf[0..($n - 1)]
                $src = $ep.Address
                Invoke-OspfLock $S { Invoke-BfdReceive -S $S -Data $data -Source $src }
            }
            Invoke-OspfLock $S { Invoke-BfdTick -S $S }
        }
        catch { Invoke-OspfLock $S { Add-OspfEvent -Session $S -Direction 'Info' -Type 'Error' -Message $_.Exception.Message } }
        $item = $null
        while ($S.Outbox.TryDequeue([ref]$item)) {
            try { $null = $S.Socket.SendTo([byte[]]$item.Bytes, [System.Net.IPEndPoint]::new($item.Destination, 3784)) } catch { }
        }
    }
}

function Start-BfdRuntime {
    param($S, [switch]$NoNetwork)
    Invoke-OspfLock $S {
        $S.Status = 'Running'
        $S.Cancel = $false
        $S.State = 'Down'; $S.Diagnostic = 0; $S.YourDisc = [long]0; $S.WasUp = $false
        $S.NextTx = [datetime]::UtcNow
        $S.DetectDeadline = [datetime]::MaxValue
        Add-OspfEvent -Session $S -Direction 'Info' -Type 'Session' -Message 'BFD started'
    }
    if ($NoNetwork) { return }
    $mk = {
        param($port)
        $u = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $u.Bind([System.Net.IPEndPoint]::new($S.LocalAddress, $port))
        $u.Ttl = 255
        $u
    }
    try {
        $S.RxSocket = & $mk 3784
        $S.Socket = & $mk 0
    }
    catch {
        foreach ($k in 'Socket', 'RxSocket') { if ($S[$k]) { $S[$k].Dispose(); $S[$k] = $null } }
        $S.Status = 'Stopped'
        throw "Cannot open BFD UDP sockets on $($S.LocalAddress) (port 3784): $($_.Exception.Message)"
    }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript({
            param($manifest, $state)
            Import-Module $manifest -Force
            & (Get-Module PowerOSPF) { param($s) Invoke-BfdRuntime -S $s } $state
        }).AddArgument($script:ModuleManifest).AddArgument($S)
    $S.Runspace = $rs; $S.PowerShell = $ps; $S.Handle = $ps.BeginInvoke()
}

function Stop-BfdRuntime {
    param($S, [switch]$Silent)
    Invoke-OspfLock $S {
        if ($S.Status -eq 'Running' -and -not $Silent) {
            Set-BfdState $S 'AdminDown' 7 'administratively down'
            Send-BfdPacket $S ([datetime]::UtcNow)
        }
    }
    $item = $null
    if ($S.Socket -and -not $S.PowerShell) { while ($S.Outbox.TryDequeue([ref]$item)) { try { $null = $S.Socket.SendTo([byte[]]$item.Bytes, [System.Net.IPEndPoint]::new($item.Destination, 3784)) } catch { } } }
    elseif ($S.PowerShell) { Start-Sleep -Milliseconds 60 }
    $S.Cancel = $true
    if ($S.PowerShell) {
        try { $null = $S.Handle.AsyncWaitHandle.WaitOne(3000); $S.PowerShell.Stop() } catch { }
        $S.PowerShell.Dispose(); $S.Runspace.Dispose()
    }
    foreach ($k in 'Socket', 'RxSocket') { if ($S[$k]) { $S[$k].Dispose(); $S[$k] = $null } }
    $S.PowerShell = $null; $S.Runspace = $null; $S.Handle = $null
    Invoke-OspfLock $S { $S.Status = 'Stopped'; $S.State = 'Down' }
}
