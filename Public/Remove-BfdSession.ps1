function Remove-BfdSession {
    <#
    .SYNOPSIS
        Stops and removes a BFD session.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name, [switch]$Silent)
    process {
        if (-not $script:BfdSessions.ContainsKey($Name)) { throw "No BFD session named '$Name'" }
        $s = $script:BfdSessions[$Name]
        if ($s.Status -eq 'Running') { Stop-BfdRuntime -S $s -Silent:$Silent }
        $script:BfdSessions.Remove($Name)
    }
}
