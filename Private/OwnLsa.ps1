function Get-OspfNextSequence {
    param($Session, [string]$Key)
    $next = $script:OspfInitialSequence
    $e = $Session.Lsdb[$Key]
    if ($e) { $next = [math]::Max($next, (Read-OspfLsaHeader $e.Bytes 0).Sequence + 1) }
    if ($Session.SeqFloor.ContainsKey($Key)) { $next = [math]::Max($next, $Session.SeqFloor[$Key] + 1) }
    [long]$next
}

function Set-OspfOwnLsa {
    # Originates (or refreshes) one self-originated LSA; floods it when its content changed.
    param($Session, [datetime]$Now, [hashtable]$Parameters, [switch]$Force)
    $key = "$($script:LsaTypeNumbers[$Parameters.Type])|$($Parameters.LinkStateId)|$($Session.RouterId)"
    $seq = Get-OspfNextSequence $Session $Key
    $lsa = New-OspfLsa @Parameters -AdvertisingRouter $Session.RouterId -Sequence $seq
    $e = $Session.Lsdb[$key]
    if ($e -and -not $Force -and $e.Originated -and (Get-OspfLsaAge $e $Now) -lt $script:OspfMaxAge) {
        $old = [byte[]]$e.Bytes
        if ($old.Length -eq $lsa.Length -and [System.Convert]::ToHexString($old[20..($old.Length - 1)]) -eq [System.Convert]::ToHexString($lsa[20..($lsa.Length - 1)])) { return $key }
    }
    $null = Install-OspfLsa $Session $lsa $Now -Originated
    $Session.Originated[$key] = $true
    $Session.SeqFloor[$key] = $seq
    Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Originate' -Message "LSA $key seq=0x$('{0:X8}' -f $seq)"
    Send-OspfFlood $Session @($key) $Now
    $key
}

function Update-OspfOwnLsas {
    param($Session, [datetime]$Now = [datetime]::UtcNow, [switch]$Force)
    $force = $Force -or [bool]$Session.ForceOriginate
    $Session.LsaDirty = $false
    $Session.ForceOriginate = $false
    if ($force) { $Session.LastRefresh = $Now }
    if ($Session.Status -ne 'Running') { return }
    $desired = [System.Collections.Generic.HashSet[string]]::new()
    $me = $Session.LocalAddress
    $full = @($Session.Neighbors.Values | Where-Object { $_.State -eq 'Full' })

    $links = [System.Collections.Generic.List[object]]::new()
    $netAddr = ConvertFrom-OspfLong $Session.NetworkLong
    if ($Session.NetworkType -eq 'PointToPoint') {
        foreach ($n in $full) { $links.Add((New-OspfRouterLink PointToPoint $n.RouterId $me -Metric $Session.Cost)) }
        $links.Add((New-OspfRouterLink Stub $netAddr $Session.Mask -Metric $Session.Cost))
    }
    else {
        $drFull = ($Session.Dr -eq $Session.LocalAddressLong -and $full.Count -gt 0) -or
        ($Session.Dr -ne 0 -and @($full | Where-Object { $_.Address -eq $Session.Dr }).Count -gt 0)
        if ($drFull) { $links.Add((New-OspfRouterLink Transit (ConvertFrom-OspfLong $Session.Dr) $me -Metric $Session.Cost)) }
        else { $links.Add((New-OspfRouterLink Stub $netAddr $Session.Mask -Metric $Session.Cost)) }
    }
    foreach ($p in $Session.Prefixes) { $links.Add((New-OspfRouterLink Stub $p.Network $p.Mask -Metric $p.Metric)) }
    $flags = 0
    if ($Session.Summaries.Count -gt 0) { $flags = $flags -bor 1 }
    if ($Session.Externals.Count -gt 0) { $flags = $flags -bor 2 }
    $null = $desired.Add((Set-OspfOwnLsa -Session $Session -Now $Now -Force:$force -Parameters @{ Type = 'Router'; LinkStateId = $Session.RouterId; Link = $links.ToArray(); Flags = $flags }))

    if ($Session.NetworkType -eq 'Broadcast' -and $Session.Dr -eq $Session.LocalAddressLong -and $full.Count -gt 0) {
        $att = @($Session.RouterId) + @($full | ForEach-Object { $_.RouterId })
        $null = $desired.Add((Set-OspfOwnLsa -Session $Session -Now $Now -Force:$force -Parameters @{ Type = 'Network'; LinkStateId = $me; Mask = $Session.Mask; AttachedRouter = $att }))
    }
    foreach ($x in $Session.Externals) {
        $null = $desired.Add((Set-OspfOwnLsa -Session $Session -Now $Now -Force:$force -Parameters @{
                    Type = 'External'; LinkStateId = $x.Network; Mask = $x.Mask; Metric = $x.Metric; ExternalType = $x.ExternalType; Tag = $x.Tag; ForwardingAddress = $x.ForwardingAddress }))
    }
    foreach ($x in $Session.Summaries) {
        $null = $desired.Add((Set-OspfOwnLsa -Session $Session -Now $Now -Force:$force -Parameters @{ Type = 'SummaryNetwork'; LinkStateId = $x.Network; Mask = $x.Mask; Metric = $x.Metric }))
    }
    foreach ($k in @($Session.Originated.Keys)) {
        if (-not $desired.Contains($k)) {
            Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Flush' -Message "Flushing LSA $k"
            Stop-OspfLsaInstance $Session $k $Now
        }
    }
}
