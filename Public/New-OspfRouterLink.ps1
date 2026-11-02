function New-OspfRouterLink {
    <#
    .SYNOPSIS
        Describes one link of a Router LSA (for New-OspfLsa -Link).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('PointToPoint', 'Transit', 'Stub', 'Virtual')][string]$Type,
        [Parameter(Mandatory)][ipaddress]$LinkId,
        [Parameter(Mandatory)][ipaddress]$LinkData,
        [ValidateRange(0, 65535)][int]$Metric = 10
    )
    [pscustomobject]@{
        PSTypeName = 'PowerOSPF.RouterLink'
        Type       = @{ PointToPoint = 1; Transit = 2; Stub = 3; Virtual = 4 }[$Type]
        LinkId     = $LinkId
        LinkData   = $LinkData
        Metric     = $Metric
    }
}
