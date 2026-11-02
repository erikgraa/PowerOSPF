function Reset-OspfNeighbor {
    <#
    .SYNOPSIS
        Forces a neighbor Down immediately, skipping the Dead interval.
    .DESCRIPTION
        Integration point for an external liveness detector: when a BFD session to the neighbor goes Down, call
        this with -Reason 'BFD Down'. -HoldDown ignores the neighbor's Hellos for that many seconds so the adjacency
        does not immediately re-form while the forwarding path is still considered dead. Also useful as fault injection.
    .EXAMPLE
        Reset-OspfNeighbor lab -Address 10.0.0.1 -Reason 'BFD Down' -HoldDown 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [ipaddress]$RouterId,
        [ipaddress]$Address,
        [string]$Reason = 'Reset requested',
        [ValidateRange(0, 86400)][int]$HoldDown = 0
    )
    if (-not $RouterId -and -not $Address) { throw 'Specify -RouterId or -Address' }
    $s = Get-OspfSessionState -Name $Name
    Invoke-OspfLock $s {
        $now = [datetime]::UtcNow
        foreach ($n in @($s.Neighbors.Values)) {
            if (($RouterId -and $n.RouterId.Equals($RouterId)) -or ($Address -and $n.Address -eq (ConvertTo-OspfLong $Address))) {
                if ($HoldDown -gt 0) { $s.HoldDown[$n.RouterId.ToString()] = $now.AddSeconds($HoldDown) }
                Remove-OspfNeighbor $s $n $Reason $now
            }
        }
        if ($s.LsaDirty) { Update-OspfOwnLsas -Session $s -Now $now }
    }
}
