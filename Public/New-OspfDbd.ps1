function New-OspfDbd {
    <#
    .SYNOPSIS
        Builds an OSPFv2 Database Description packet as byte[]. -LsaHeader accepts LSA headers or whole LSAs (first 20 bytes are used).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [ipaddress]$AreaId = '0.0.0.0',
        [ValidateRange(0, 65535)][int]$InterfaceMtu = 1500,
        [ValidateRange(0, 255)][int]$Options = 2,
        [switch]$Init,
        [switch]$More,
        [switch]$Master,
        [long]$Sequence = 1,
        $LsaHeader = @(),
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1,
        [long]$CryptoSequence = 0,
        [switch]$CorruptChecksum
    )
    $flags = 0
    if ($Init) { $flags = $flags -bor 4 }
    if ($More) { $flags = $flags -bor 2 }
    if ($Master) { $flags = $flags -bor 1 }
    $body = Get-OspfDbdBody -InterfaceMtu $InterfaceMtu -Options $Options -Flags $flags -Sequence $Sequence -Headers $LsaHeader
    New-OspfPacketBytes -Type 2 -RouterId $RouterId -AreaId $AreaId -Body $body -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId -CryptoSequence $CryptoSequence -CorruptChecksum:$CorruptChecksum
}
