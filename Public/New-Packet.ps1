function ConvertTo-PacketFieldBytes {
    param($Field)
    $v = $Field.Value
    if ($v -is [byte[]]) { return , $v }
    if ($v -is [ipaddress]) { return , [byte[]]$v.GetAddressBytes() }
    if ($v -is [string]) {
        $hex = $v -replace '[:\s-]', ''
        if ($hex.Length % 2 -ne 0 -or $hex -notmatch '^[0-9A-Fa-f]*$') { throw "Field '$($Field.Name)': '$v' is not a valid hex string" }
        return , [byte[]][System.Convert]::FromHexString($hex)
    }
    if ($v -is [ValueType] -and $v -isnot [bool]) {
        if ($Field.Bytes -lt 1 -or $Field.Bytes -gt 8) { throw "Field '$($Field.Name)': integers need -Bytes between 1 and 8" }
        $n = [System.Numerics.BigInteger]$v
        $max = [System.Numerics.BigInteger]::Pow(2, 8 * $Field.Bytes)
        if ($n.Sign -lt 0 -or $n -ge $max) { throw "Field '$($Field.Name)': value $v does not fit in $($Field.Bytes) byte(s)" }
        $out = [byte[]]::new($Field.Bytes)
        for ($i = $Field.Bytes - 1; $i -ge 0; $i--) {
            $out[$i] = [byte]($n % 256)
            $n = [System.Numerics.BigInteger]::Divide($n, 256)
        }
        return , $out
    }
    throw "Field '$($Field.Name)': unsupported value type $($v.GetType().Name)"
}

function New-Packet {
    <#
    .SYNOPSIS
        Concatenates packet fields into a byte[]; optionally fills a length field with the total length.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Field,
        [string]$LengthField
    )
    $parts = [ordered]@{}
    $i = 0
    foreach ($f in $Field) {
        $parts["$i|$($f.Name)"] = [byte[]](ConvertTo-PacketFieldBytes $f)
        $i++
    }
    $total = 0
    foreach ($p in $parts.Values) { $total += $p.Length }
    if ($LengthField) {
        $key = @($parts.Keys | Where-Object { $_ -like "*|$LengthField" })
        if ($key.Count -eq 0) { throw "Length field '$LengthField' not found" }
        $lf = $Field | Where-Object { $_.Name -eq $LengthField } | Select-Object -First 1
        $parts[$key[0]] = [byte[]](ConvertTo-PacketFieldBytes (New-PacketField $LengthField $total -Bytes $lf.Bytes))
    }
    $l = [System.Collections.Generic.List[byte]]::new()
    foreach ($p in $parts.Values) { $l.AddRange($p) }
    , $l.ToArray()
}
