function Get-OspfEvent {
    <#
    .SYNOPSIS
        Returns the last 500 sent/received packets and state changes of a session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$Type,
        [string]$Neighbor,
        [int]$Last
    )
    $s = Get-OspfSessionState -Name $Name
    $ev = Invoke-OspfLock $s { $s.Events.ToArray() }
    if ($Type) { $ev = @($ev | Where-Object { $_.Type -eq $Type }) }
    if ($Neighbor) { $ev = @($ev | Where-Object { $_.Neighbor -eq $Neighbor }) }
    if ($Last -gt 0) { $ev = @($ev | Select-Object -Last $Last) }
    $ev
}
