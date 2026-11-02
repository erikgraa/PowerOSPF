function Get-OspfNeighbor {
    <#
    .SYNOPSIS
        Lists OSPF neighbors of a session with their state machine state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Name,
        [ipaddress]$RouterId
    )
    $list = if ($Name) { @(Get-OspfSessionState -Name $Name) } else { @(Get-OspfSessionState) }
    foreach ($s in $list) {
        $now = [datetime]::UtcNow
        $rows = Invoke-OspfLock $s {
            foreach ($n in @($s.Neighbors.Values)) {
                [pscustomobject]@{
                    PSTypeName             = 'PowerOSPF.Neighbor'
                    Session                = $s.Name
                    RouterId               = $n.RouterId
                    Address                = ConvertFrom-OspfLong $n.Address
                    State                  = $n.State
                    Priority               = $n.Priority
                    DesignatedRouter       = ConvertFrom-OspfLong $n.Dr
                    BackupDesignatedRouter = ConvertFrom-OspfLong $n.Bdr
                    Options                = $n.Options
                    IsMaster               = [bool]$n.IsMaster
                    DeadInSeconds          = [int][math]::Max(0, ($n.Deadline - $now).TotalSeconds)
                    RequestListCount       = $n.RequestList.Count
                    RetransmitListCount    = $n.Retrans.Count
                }
            }
        }
        foreach ($r in $rows) {
            if (-not $RouterId -or $r.RouterId.Equals($RouterId)) { $r }
        }
    }
}
