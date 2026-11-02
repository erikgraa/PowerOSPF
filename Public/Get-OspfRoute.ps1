function Get-OspfRoute {
    <#
    .SYNOPSIS
        Runs SPF over the session's LSDB and returns intra-area, inter-area and external routes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string]$Name)
    $s = Get-OspfSessionState -Name $Name
    Invoke-OspfLock $s { Invoke-OspfSpf -Session $s -Now ([datetime]::UtcNow) }
}
