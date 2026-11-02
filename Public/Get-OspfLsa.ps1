function Get-OspfLsa {
    <#
    .SYNOPSIS
        Returns the link-state database of a session (ages are current).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Name,
        [ValidateSet('Router', 'Network', 'SummaryNetwork', 'SummaryAsbr', 'External')][string]$Type,
        [ipaddress]$AdvertisingRouter,
        [ipaddress]$LinkStateId
    )
    $list = if ($Name) { @(Get-OspfSessionState -Name $Name) } else { @(Get-OspfSessionState) }
    foreach ($s in $list) {
        $now = [datetime]::UtcNow
        $rows = Invoke-OspfLock $s {
            foreach ($e in @($s.Lsdb.Values)) {
                $l = Read-OspfLsa ([byte[]](Get-OspfEntryBytes $e $now)) 0
                Add-Member -InputObject $l -NotePropertyMembers @{ Session = $s.Name; Originated = [bool]$e.Originated } -Force
                $l
            }
        }
        foreach ($l in $rows) {
            if ($Type -and $l.TypeName -ne $Type) { continue }
            if ($AdvertisingRouter -and -not $l.AdvertisingRouter.Equals($AdvertisingRouter)) { continue }
            if ($LinkStateId -and -not $l.LinkStateId.Equals($LinkStateId)) { continue }
            $l
        }
    }
}
