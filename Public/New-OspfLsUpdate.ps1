function New-OspfLsUpdate {
    <#
    .SYNOPSIS
        Builds an OSPFv2 Link State Update packet carrying the given LSAs (byte[] from New-OspfLsa).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [ipaddress]$AreaId = '0.0.0.0',
        [Parameter(Mandatory)]$Lsa,
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1,
        [long]$CryptoSequence = 0,
        [switch]$CorruptChecksum
    )
    $body = Get-OspfLsuBody -Lsas $Lsa
    New-OspfPacketBytes -Type 4 -RouterId $RouterId -AreaId $AreaId -Body $body -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId -CryptoSequence $CryptoSequence -CorruptChecksum:$CorruptChecksum
}
