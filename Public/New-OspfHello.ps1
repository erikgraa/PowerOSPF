function New-OspfHello {
    <#
    .SYNOPSIS
        Builds an OSPFv2 Hello packet (without IP header) as byte[].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [ipaddress]$AreaId = '0.0.0.0',
        [ipaddress]$NetworkMask = '255.255.255.0',
        [ValidateRange(0, 65535)][int]$HelloInterval = 10,
        [long]$DeadInterval = 40,
        [ValidateRange(0, 255)][int]$Options = 2,
        [ValidateRange(0, 255)][int]$Priority = 1,
        [ipaddress]$DesignatedRouter = '0.0.0.0',
        [ipaddress]$BackupDesignatedRouter = '0.0.0.0',
        [ipaddress[]]$Neighbor = @(),
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [int]$KeyId = 1,
        [long]$CryptoSequence = 0,
        [switch]$CorruptChecksum
    )
    $n = [long[]]@($Neighbor | ForEach-Object { ConvertTo-OspfLong $_ })
    $body = Get-OspfHelloBody -Mask $NetworkMask -HelloInterval $HelloInterval -Options $Options -Priority $Priority -DeadInterval $DeadInterval `
        -Dr (ConvertTo-OspfLong $DesignatedRouter) -Bdr (ConvertTo-OspfLong $BackupDesignatedRouter) -Neighbors $n
    New-OspfPacketBytes -Type 1 -RouterId $RouterId -AreaId $AreaId -Body $body -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId -CryptoSequence $CryptoSequence -CorruptChecksum:$CorruptChecksum
}
