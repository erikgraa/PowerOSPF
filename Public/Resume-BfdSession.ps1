function Resume-BfdSession {
    <#
    .SYNOPSIS
        Restarts a stopped BFD session.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name, [switch]$NoNetwork)
    process {
        if (-not $script:BfdSessions.ContainsKey($Name)) { throw "No BFD session named '$Name'" }
        $s = $script:BfdSessions[$Name]
        if ($s.Status -ne 'Running') { Start-BfdRuntime -S $s -NoNetwork:$NoNetwork }
    }
}
