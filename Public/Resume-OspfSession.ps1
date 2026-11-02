function Resume-OspfSession {
    <#
    .SYNOPSIS
        Restarts a stopped session with its existing configuration; adjacencies and the LSDB are rebuilt from scratch.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name,
        [switch]$NoNetwork
    )
    process {
        $s = Get-OspfSessionState -Name $Name
        if ($s.Status -eq 'Running') { return }
        Start-OspfRuntime -Session $s -NoNetwork:$NoNetwork
    }
}
