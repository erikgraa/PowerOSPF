function Update-OspfSession {
    <#
    .SYNOPSIS
        Re-originates the session's own LSAs now, optionally sends a Hello immediately or resets adjacencies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name,
        [switch]$ResetNeighbors,
        [switch]$HelloNow
    )
    process {
        $s = Get-OspfSessionState -Name $Name
        Invoke-OspfLock $s {
            $now = [datetime]::UtcNow
            if ($s.Status -ne 'Running') { throw "Session '$Name' is not running" }
            if ($ResetNeighbors) {
                foreach ($n in @($s.Neighbors.Values)) {
                    if ($script:NeighborRank[$n.State] -ge $script:NeighborRank['ExStart']) { Restart-OspfAdjacency $s $n 'Reset requested' $now }
                }
            }
            if ($HelloNow) { Send-OspfHello $s }
            Update-OspfOwnLsas -Session $s -Now $now -Force
        }
    }
}
