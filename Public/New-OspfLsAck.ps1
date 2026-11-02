function New-OspfLsAck {
    <#
    .SYNOPSIS
        Builds an OSPFv2 Link State Acknowledgment packet. -LsaHeader accepts headers or whole LSAs (first 20 bytes are used).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [ipaddress]$AreaId = '0.0.0.0',
        [Parameter(Mandatory)]$LsaHeader,
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1,
        [long]$CryptoSequence = 0,
        [switch]$CorruptChecksum
    )
    $body = Get-OspfLsAckBody -Headers $LsaHeader
    New-OspfPacketBytes -Type 5 -RouterId $RouterId -AreaId $AreaId -Body $body -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId -CryptoSequence $CryptoSequence -CorruptChecksum:$CorruptChecksum
}
