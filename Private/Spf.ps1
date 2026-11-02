function Invoke-OspfSpf {
    <#
    Shortest-path-first over the Router/Network LSAs of the LSDB (RFC 2328 16.1), plus summary and external routes (16.2, 16.4).
    #>
    param($Session, [datetime]$Now = [datetime]::UtcNow)
    $routers = @{}
    $networks = @{}
    $others = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $Session.Lsdb.Values) {
        if ((Get-OspfLsaAge $e $Now) -ge $script:OspfMaxAge) { continue }
        $l = Read-OspfLsa ([byte[]]$e.Bytes) 0
        switch ($l.Type) {
            1 { $routers["$($l.AdvertisingRouter)"] = $l }
            2 { $networks["$($l.LinkStateId)"] = $l }
            default { $others.Add($l) }
        }
    }
    $rootKey = "R|$($Session.RouterId)"
    $dist = @{ $rootKey = 0 }
    $nh = @{ $rootKey = '' }
    $done = @{}
    $candidates = [System.Collections.Generic.HashSet[string]]::new()
    $null = $candidates.Add($rootKey)
    $stubs = @{}
    $addRoute = {
        param($Prefix, $Cost, $NextHop, $Rank, $Type, $Adv)
        $cur = $stubs[$Prefix.Key]
        if (-not $cur -or $Rank -lt $cur.Rank -or ($Rank -eq $cur.Rank -and $Cost -lt $cur.Cost)) {
            $stubs[$Prefix.Key] = [pscustomobject]@{
                PSTypeName = 'PowerOSPF.Route'; Prefix = $Prefix.Network; PrefixLength = $Prefix.Length; Type = $Type
                Cost = $Cost; NextHop = $(if ($NextHop) { [ipaddress]$NextHop } else { $null }); AdvertisingRouter = $Adv; Rank = $Rank; Key = $Prefix.Key
            }
        }
    }
    $mkPrefix = {
        param([ipaddress]$Net, [ipaddress]$Mask)
        $m = ConvertTo-OspfLong $Mask
        $len = 0
        for ($i = 31; $i -ge 0; $i--) { if (($m -shr $i) -band 1) { $len++ } else { break } }
        $net = ConvertFrom-OspfLong ((ConvertTo-OspfLong $Net) -band $m)
        [pscustomobject]@{ Network = $net; Length = $len; Key = "$net/$len" }
    }
    while ($true) {
        $best = $null
        foreach ($c in $candidates) { if (-not $done[$c] -and ($null -eq $best -or $dist[$c] -lt $dist[$best])) { $best = $c } }
        if ($null -eq $best) { break }
        $done[$best] = $true
        $kind, $id = $best.Split('|')
        $d = $dist[$best]
        if ($kind -eq 'R') {
            $r = $routers[$id]
            if (-not $r) { continue }
            foreach ($lk in $r.Links) {
                switch ($lk.Type) {
                    3 {
                        $p = & $mkPrefix $lk.LinkId $lk.LinkData
                        & $addRoute $p ($d + $lk.Metric) $nh[$best] 0 'IntraArea' $r.AdvertisingRouter
                    }
                    { $_ -in 1, 2 } {
                        $tk = if ($lk.Type -eq 1) { "R|$($lk.LinkId)" } else { "N|$($lk.LinkId)" }
                        $target = if ($lk.Type -eq 1) { $routers["$($lk.LinkId)"] } else { $networks["$($lk.LinkId)"] }
                        if (-not $target) { continue }
                        $nd = $d + $lk.Metric
                        if ($done[$tk]) { continue }
                        if (-not $dist.ContainsKey($tk) -or $nd -lt $dist[$tk]) {
                            $dist[$tk] = $nd
                            $hop = $nh[$best]
                            if ($best -eq $rootKey) {
                                if ($lk.Type -eq 2) { $hop = '' }
                                else {
                                    $back = $target.Links | Where-Object { $_.Type -eq 1 -and $_.LinkId.Equals($Session.RouterId) } | Select-Object -First 1
                                    $hop = if ($back) { "$($back.LinkData)" } else { '' }
                                }
                            }
                            $nh[$tk] = $hop
                            $null = $candidates.Add($tk)
                        }
                    }
                }
            }
        }
        else {
            $net = $networks[$id]
            if (-not $net) { continue }
            $p = & $mkPrefix $net.LinkStateId $net.NetworkMask
            & $addRoute $p $d $nh[$best] 0 'IntraArea' $net.AdvertisingRouter
            foreach ($ar in $net.AttachedRouters) {
                $tk = "R|$ar"
                $target = $routers["$ar"]
                if (-not $target -or $done[$tk]) { continue }
                if (-not $dist.ContainsKey($tk) -or $d -lt $dist[$tk]) {
                    $dist[$tk] = $d
                    $hop = $nh[$best]
                    if ($hop -eq '') {
                        $back = $target.Links | Where-Object { $_.Type -eq 2 -and $_.LinkId.Equals($net.LinkStateId) } | Select-Object -First 1
                        $hop = if ($back) { "$($back.LinkData)" } else { '' }
                    }
                    $nh[$tk] = $hop
                    $null = $candidates.Add($tk)
                }
            }
        }
    }
    foreach ($l in $others) {
        if ($l.AdvertisingRouter.Equals($Session.RouterId)) { continue }
        $ak = "R|$($l.AdvertisingRouter)"
        if (-not $dist.ContainsKey($ak) -or -not $l.NetworkMask) { continue }
        $p = & $mkPrefix $l.LinkStateId $l.NetworkMask
        if ($l.Type -eq 3) { & $addRoute $p ($dist[$ak] + $l.Metric) $nh[$ak] 1 'InterArea' $l.AdvertisingRouter }
        elseif ($l.Type -eq 5 -and $l.ForwardingAddress.Equals([ipaddress]'0.0.0.0')) {
            if ($l.ExternalType -eq 1) { & $addRoute $p ($dist[$ak] + $l.Metric) $nh[$ak] 2 'External1' $l.AdvertisingRouter }
            else { & $addRoute $p $l.Metric $nh[$ak] 3 'External2' $l.AdvertisingRouter }
        }
    }
    @($stubs.Values | Sort-Object Rank, Key | Select-Object Prefix, PrefixLength, Type, Cost, NextHop, AdvertisingRouter)
}
