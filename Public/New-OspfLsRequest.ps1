function New-OspfLsRequest {
    <#
    .SYNOPSIS
        Builds an OSPFv2 Link State Request packet. Each -Request needs Type (1-5 or name), LinkStateId and AdvertisingRouter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [ipaddress]$AreaId = '0.0.0.0',
        [Parameter(Mandatory)][object[]]$Request,
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1,
        [long]$CryptoSequence = 0,
        [switch]$CorruptChecksum
    )
    $body = Get-OspfLsrBody -Requests $Request
    New-OspfPacketBytes -Type 3 -RouterId $RouterId -AreaId $AreaId -Body $body -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId -CryptoSequence $CryptoSequence -CorruptChecksum:$CorruptChecksum
}
