function Read-OspfLsaHeader {
    param([byte[]]$Data, [int]$Offset = 0)
    if ($Data.Length - $Offset -lt 20) { throw 'Truncated LSA header' }
    $type = [int]$Data[$Offset + 3]
    $id = Get-OspfIp $Data ($Offset + 4)
    $adv = Get-OspfIp $Data ($Offset + 8)
    $seq = Get-OspfUInt $Data ($Offset + 12) 4
    [pscustomobject]@{
        Age               = [int](Get-OspfUInt $Data $Offset 2)
        Options           = [int]$Data[$Offset + 2]
        Type              = $type
        TypeName          = $script:LsaTypeNames[$type]
        LinkStateId       = $id
        AdvertisingRouter = $adv
        Sequence          = $seq
        SequenceHex       = '0x{0:X8}' -f $seq
        Checksum          = [int](Get-OspfUInt $Data ($Offset + 16) 2)
        Length            = [int](Get-OspfUInt $Data ($Offset + 18) 2)
        Key               = "$type|$id|$adv"
    }
}

function Read-OspfLsa {
    param([byte[]]$Data, [int]$Offset = 0)
    $h = Read-OspfLsaHeader $Data $Offset
    $len = $h.Length
    if ($len -lt 20 -or $Offset + $len -gt $Data.Length) { throw "Invalid LSA length $len" }
    $b = [byte[]]$Data[$Offset..($Offset + $len - 1)]
    $extra = [ordered]@{ ChecksumValid = (Test-OspfLsaChecksum $b); Bytes = $b }
    switch ($h.Type) {
        1 {
            $links = [System.Collections.Generic.List[object]]::new()
            $extra.Flags = if ($len -ge 24) { [int]$b[20] } else { 0 }
            $n = if ($len -ge 24) { [int](Get-OspfUInt $b 22 2) } else { 0 }
            $o = 24
            $linkTypes = @{ 1 = 'PointToPoint'; 2 = 'Transit'; 3 = 'Stub'; 4 = 'Virtual' }
            for ($i = 0; $i -lt $n -and $o + 12 -le $len; $i++) {
                $lt = [int]$b[$o + 8]
                $links.Add([pscustomobject]@{
                        Type = $lt; TypeName = $linkTypes[$lt]
                        LinkId = (Get-OspfIp $b $o); LinkData = (Get-OspfIp $b ($o + 4))
                        Metric = [int](Get-OspfUInt $b ($o + 10) 2)
                    })
                $o += 12 + 4 * [int]$b[$o + 9]
            }
            $extra.Links = $links.ToArray()
        }
        2 {
            if ($len -ge 24) {
                $extra.NetworkMask = Get-OspfIp $b 20
                $r = for ($o = 24; $o + 4 -le $len; $o += 4) { Get-OspfIp $b $o }
                $extra.AttachedRouters = @($r)
            }
        }
        { $_ -in 3, 4 } {
            if ($len -ge 28) {
                $extra.NetworkMask = Get-OspfIp $b 20
                $extra.Metric = [int](Get-OspfUInt $b 25 3)
            }
        }
        5 {
            if ($len -ge 36) {
                $extra.NetworkMask = Get-OspfIp $b 20
                $extra.ExternalType = if (($b[24] -band 0x80) -ne 0) { 2 } else { 1 }
                $extra.Metric = [int](Get-OspfUInt $b 25 3)
                $extra.ForwardingAddress = Get-OspfIp $b 28
                $extra.Tag = Get-OspfUInt $b 32 4
            }
        }
    }
    Add-Member -InputObject $h -NotePropertyMembers $extra -Force
    $h
}

function Compare-OspfLsaInstance {
    # 1 if A is the more recent instance, -1 if B, 0 if identical (RFC 2328 13.1).
    param($A, $B)
    $sa = if ($A.Sequence -ge 2147483648) { $A.Sequence - 4294967296 } else { $A.Sequence }
    $sb = if ($B.Sequence -ge 2147483648) { $B.Sequence - 4294967296 } else { $B.Sequence }
    if ($sa -ne $sb) { return $(if ($sa -gt $sb) { 1 } else { -1 }) }
    if ($A.Checksum -ne $B.Checksum) { return $(if ($A.Checksum -gt $B.Checksum) { 1 } else { -1 }) }
    $aMax = $A.Age -ge $script:OspfMaxAge
    $bMax = $B.Age -ge $script:OspfMaxAge
    if ($aMax -and -not $bMax) { return 1 }
    if ($bMax -and -not $aMax) { return -1 }
    if ([math]::Abs($A.Age - $B.Age) -gt 900) { return $(if ($A.Age -lt $B.Age) { 1 } else { -1 }) }
    0
}
