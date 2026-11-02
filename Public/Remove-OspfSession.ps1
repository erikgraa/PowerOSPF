function Remove-OspfSession {
    <#
    .SYNOPSIS
        Stops a session and removes it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name, [switch]$Silent)
    process {
        $s = Get-OspfSessionState -Name $Name
        if ($s.Status -eq 'Running') { Stop-OspfRuntime -Session $s -Silent:$Silent }
        $script:OspfSessions.Remove($Name)
    }
}
