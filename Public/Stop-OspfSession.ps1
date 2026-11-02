function Stop-OspfSession {
    <#
    .SYNOPSIS
        Stops the session's runtime. Sends a goodbye Hello (empty neighbor list) unless -Silent, which lets the peer's dead timer expire.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name,
        [switch]$Silent
    )
    process {
        $s = Get-OspfSessionState -Name $Name
        if ($s.Status -eq 'Running') { Stop-OspfRuntime -Session $s -Silent:$Silent }
    }
}
