function Stop-BfdSession {
    <#
    .SYNOPSIS
        Stops a BFD session, signalling AdminDown to the peer unless -Silent.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name, [switch]$Silent)
    process {
        if (-not $script:BfdSessions.ContainsKey($Name)) { throw "No BFD session named '$Name'" }
        $s = $script:BfdSessions[$Name]
        if ($s.Status -eq 'Running') { Stop-BfdRuntime -S $s -Silent:$Silent }
    }
}
