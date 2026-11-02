function New-OspfPacketBytes {
    param(
        [Parameter(Mandatory)][int]$Type,
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [ipaddress]$AreaId = '0.0.0.0',
        [byte[]]$Body = @(),
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1,
        [long]$CryptoSequence = 0,
        [switch]$CorruptChecksum
    )
    $total = 24 + $Body.Length
    $au = $script:AuthTypeNumbers[$AuthType]
    $pkt = [byte[]](Join-OspfBytes (ConvertTo-OspfBytes 2 1) (ConvertTo-OspfBytes $Type 1) (ConvertTo-OspfBytes $total 2) `
            $RouterId.GetAddressBytes() $AreaId.GetAddressBytes() (ConvertTo-OspfBytes 0 2) (ConvertTo-OspfBytes $au 2) `
            (ConvertTo-OspfBytes 0 8) $Body)
    switch ($AuthType) {
        'None' {
            $ck = Get-InternetChecksum $pkt
            if ($CorruptChecksum) { $ck = $ck -bxor 0xFFFF }
            $pkt[12] = [byte]($ck -shr 8); $pkt[13] = [byte]($ck -band 0xFF)
        }
        'Simple' {
            $ck = Get-InternetChecksum $pkt
            if ($CorruptChecksum) { $ck = $ck -bxor 0xFFFF }
            $pkt[12] = [byte]($ck -shr 8); $pkt[13] = [byte]($ck -band 0xFF)
            $kb = [System.Text.Encoding]::ASCII.GetBytes($AuthKey)
            for ($i = 0; $i -lt 8 -and $i -lt $kb.Length; $i++) { $pkt[16 + $i] = $kb[$i] }
        }
        'Md5' {
            $pkt[18] = [byte]$KeyId
            $pkt[19] = 16
            $sb = ConvertTo-OspfBytes $CryptoSequence 4
            for ($i = 0; $i -lt 4; $i++) { $pkt[20 + $i] = $sb[$i] }
            $digest = Get-OspfMd5Digest -Packet $pkt -Key $AuthKey
            if ($CorruptChecksum) { $digest[0] = $digest[0] -bxor 0xFF }
            $pkt = [byte[]](Join-OspfBytes $pkt $digest)
        }
    }
    , $pkt
}

function Get-OspfMd5Digest {
    param([byte[]]$Packet, [string]$Key)
    $k = [byte[]]::new(16)
    $kb = [System.Text.Encoding]::ASCII.GetBytes($Key)
    for ($i = 0; $i -lt 16 -and $i -lt $kb.Length; $i++) { $k[$i] = $kb[$i] }
    , [byte[]][System.Security.Cryptography.MD5]::HashData([byte[]](Join-OspfBytes $Packet $k))
}

function Test-OspfPacketChecksum {
    param([byte[]]$Data)
    if ($Data.Length -lt 24) { return $false }
    $len = [int](Get-OspfUInt $Data 2 2)
    if ($len -lt 24 -or $len -gt $Data.Length) { return $false }
    $copy = [byte[]]$Data[0..($len - 1)]
    $stored = Get-OspfUInt $copy 12 2
    $copy[12] = 0; $copy[13] = 0
    for ($i = 16; $i -lt 24; $i++) { $copy[$i] = 0 }
    (Get-InternetChecksum $copy) -eq $stored
}

function Test-OspfPacketAuth {
    param([byte[]]$Data, [string]$AuthKey)
    $au = [int](Get-OspfUInt $Data 14 2)
    $len = [int](Get-OspfUInt $Data 2 2)
    switch ($au) {
        0 { return $true }
        1 {
            $kb = [byte[]]::new(8)
            $ab = [System.Text.Encoding]::ASCII.GetBytes($AuthKey)
            for ($i = 0; $i -lt 8 -and $i -lt $ab.Length; $i++) { $kb[$i] = $ab[$i] }
            return ([System.Convert]::ToHexString($kb) -eq [System.Convert]::ToHexString([byte[]]$Data[16..23]))
        }
        2 {
            if ($Data.Length -lt $len + 16) { return $false }
            $d = Get-OspfMd5Digest -Packet ([byte[]]$Data[0..($len - 1)]) -Key $AuthKey
            return ([System.Convert]::ToHexString($d) -eq [System.Convert]::ToHexString([byte[]]$Data[$len..($len + 15)]))
        }
        default { return $false }
    }
}

function Get-OspfHelloBody {
    param([ipaddress]$Mask, [int]$HelloInterval, [int]$Options, [int]$Priority, [long]$DeadInterval, [long]$Dr, [long]$Bdr, [long[]]$Neighbors = @())
    $parts = @($Mask.GetAddressBytes(), (ConvertTo-OspfBytes $HelloInterval 2), (ConvertTo-OspfBytes $Options 1), (ConvertTo-OspfBytes $Priority 1),
        (ConvertTo-OspfBytes $DeadInterval 4), (ConvertTo-OspfBytes $Dr 4), (ConvertTo-OspfBytes $Bdr 4))
    foreach ($n in $Neighbors) { $parts += , (ConvertTo-OspfBytes $n 4) }
    Join-OspfBytes @parts
}

function Get-OspfDbdBody {
    param([int]$InterfaceMtu, [int]$Options, [int]$Flags, [long]$Sequence, $Headers = @())
    $l = [System.Collections.Generic.List[byte]]::new()
    $l.AddRange([byte[]](ConvertTo-OspfBytes $InterfaceMtu 2))
    $l.AddRange([byte[]](ConvertTo-OspfBytes $Options 1))
    $l.AddRange([byte[]](ConvertTo-OspfBytes $Flags 1))
    $l.AddRange([byte[]](ConvertTo-OspfBytes $Sequence 4))
    foreach ($h in (ConvertTo-OspfByteList $Headers)) { $l.AddRange([byte[]]$h[0..19]) }
    , $l.ToArray()
}

function Get-OspfLsrBody {
    param($Requests)
    $l = [System.Collections.Generic.List[byte]]::new()
    foreach ($r in $Requests) {
        $t = $r.Type
        if ($t -is [string]) { $t = $script:LsaTypeNumbers[$t] }
        $l.AddRange([byte[]](ConvertTo-OspfBytes $t 4))
        $l.AddRange([byte[]]([ipaddress]$r.LinkStateId).GetAddressBytes())
        $l.AddRange([byte[]]([ipaddress]$r.AdvertisingRouter).GetAddressBytes())
    }
    , $l.ToArray()
}

function Get-OspfLsuBody {
    param($Lsas)
    $list = ConvertTo-OspfByteList $Lsas
    $l = [System.Collections.Generic.List[byte]]::new()
    $l.AddRange([byte[]](ConvertTo-OspfBytes $list.Count 4))
    foreach ($x in $list) { $l.AddRange($x) }
    , $l.ToArray()
}

function Get-OspfLsAckBody {
    param($Headers)
    $l = [System.Collections.Generic.List[byte]]::new()
    foreach ($h in (ConvertTo-OspfByteList $Headers)) { $l.AddRange([byte[]]$h[0..19]) }
    , $l.ToArray()
}
