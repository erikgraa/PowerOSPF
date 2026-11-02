$script:LsaTypeNames = @{ 1 = 'Router'; 2 = 'Network'; 3 = 'SummaryNetwork'; 4 = 'SummaryAsbr'; 5 = 'External' }
$script:LsaTypeNumbers = @{ Router = 1; Network = 2; SummaryNetwork = 3; SummaryAsbr = 4; External = 5 }
$script:PacketTypeNames = @{ 1 = 'Hello'; 2 = 'DatabaseDescription'; 3 = 'LinkStateRequest'; 4 = 'LinkStateUpdate'; 5 = 'LinkStateAck' }
$script:AuthTypeNumbers = @{ None = 0; Simple = 1; Md5 = 2 }
$script:AuthTypeNames = @{ 0 = 'None'; 1 = 'Simple'; 2 = 'Md5' }
$script:NeighborRank = @{ 'Down' = 0; 'Init' = 1; '2-Way' = 2; 'ExStart' = 3; 'Exchange' = 4; 'Loading' = 5; 'Full' = 6 }

$script:OspfMaxAge = 3600
$script:OspfInitialSequence = [long]2147483649
$script:AllSpfRouters = [ipaddress]'224.0.0.5'
$script:AllDRouters = [ipaddress]'224.0.0.6'

function ConvertTo-OspfBytes {
    param(
        [Parameter(Mandatory, Position = 0)][long]$Value,
        [Parameter(Mandatory, Position = 1)][int]$Count
    )
    $b = [byte[]]::new($Count)
    for ($i = $Count - 1; $i -ge 0; $i--) {
        $b[$i] = [byte]($Value -band 0xFF)
        $Value = $Value -shr 8
    }
    , $b
}

function Get-OspfUInt {
    param(
        [Parameter(Mandatory, Position = 0)][byte[]]$Bytes,
        [Parameter(Mandatory, Position = 1)][int]$Offset,
        [Parameter(Mandatory, Position = 2)][int]$Count
    )
    [long]$v = 0
    for ($i = 0; $i -lt $Count; $i++) {
        $v = ($v -shl 8) -bor [long]$Bytes[$Offset + $i]
    }
    $v
}

function Get-OspfIp {
    param([byte[]]$Bytes, [int]$Offset)
    [ipaddress]::new([byte[]]$Bytes[$Offset..($Offset + 3)])
}

function ConvertTo-OspfLong {
    param([Parameter(Mandatory, Position = 0)][ipaddress]$Address)
    Get-OspfUInt -Bytes $Address.GetAddressBytes() -Offset 0 -Count 4
}

function ConvertFrom-OspfLong {
    param([Parameter(Mandatory, Position = 0)][long]$Value)
    [ipaddress]::new([byte[]](ConvertTo-OspfBytes -Value $Value -Count 4))
}

function Join-OspfBytes {
    param([Parameter(ValueFromRemainingArguments)]$Parts)
    $l = [System.Collections.Generic.List[byte]]::new()
    foreach ($p in $Parts) {
        if ($null -ne $p) { $l.AddRange([byte[]]$p) }
    }
    , $l.ToArray()
}

function ConvertTo-OspfByteList {
    param($InputObject)
    $list = [System.Collections.Generic.List[byte[]]]::new()
    if ($null -eq $InputObject) { }
    elseif ($InputObject -is [byte[]]) { $list.Add($InputObject) }
    else { foreach ($i in $InputObject) { $list.Add([byte[]]$i) } }
    , $list.ToArray()
}

function ConvertFrom-OspfPrefix {
    param([Parameter(Mandatory, Position = 0)][string]$Prefix)
    $parts = $Prefix.Split('/')
    if ($parts.Count -ne 2) { throw "Invalid prefix '$Prefix' (expected a.b.c.d/len)" }
    $len = [int]$parts[1]
    if ($len -lt 0 -or $len -gt 32) { throw "Invalid prefix length in '$Prefix'" }
    $maskLong = ([long]4294967295 -shl (32 - $len)) -band [long]4294967295
    $addr = ConvertTo-OspfLong ([ipaddress]$parts[0])
    [pscustomobject]@{
        Network      = ConvertFrom-OspfLong ($addr -band $maskLong)
        PrefixLength = $len
        Mask         = ConvertFrom-OspfLong $maskLong
        NetworkLong  = $addr -band $maskLong
        MaskLong     = $maskLong
    }
}

function Get-InternetChecksum {
    param([byte[]]$Data)
    [long]$sum = 0
    for ($i = 0; $i + 1 -lt $Data.Length; $i += 2) {
        $sum += (([long]$Data[$i] -shl 8) + [long]$Data[$i + 1])
    }
    if ($Data.Length % 2 -eq 1) { $sum += ([long]$Data[$Data.Length - 1] -shl 8) }
    while (($sum -shr 16) -ne 0) { $sum = ($sum -band 0xFFFF) + ($sum -shr 16) }
    [int]((-bnot $sum) -band 0xFFFF)
}

function Set-OspfLsaChecksum {
    # ISO 8473 Fletcher checksum (RFC 905 Annex B), computed in place; the age field is excluded.
    param([byte[]]$Lsa)
    $Lsa[16] = 0
    $Lsa[17] = 0
    $len = $Lsa.Length - 2
    $c0 = 0
    $c1 = 0
    for ($i = 2; $i -lt $Lsa.Length; $i++) {
        $c0 = ($c0 + $Lsa[$i]) % 255
        $c1 = ($c1 + $c0) % 255
    }
    $x = (($len - 15) * $c0 - $c1) % 255
    if ($x -le 0) { $x += 255 }
    $y = 510 - $c0 - $x
    if ($y -gt 255) { $y -= 255 }
    $Lsa[16] = [byte]$x
    $Lsa[17] = [byte]$y
}

function Test-OspfLsaChecksum {
    param([byte[]]$Lsa)
    if ($Lsa.Length -lt 20) { return $false }
    $c0 = 0
    $c1 = 0
    for ($i = 2; $i -lt $Lsa.Length; $i++) {
        $c0 = ($c0 + $Lsa[$i]) % 255
        $c1 = ($c1 + $c0) % 255
    }
    ($c0 -eq 0 -and $c1 -eq 0)
}
