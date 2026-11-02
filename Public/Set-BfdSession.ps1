function Set-BfdSession {
    <#
    .SYNOPSIS
        Changes a BFD session; -SuppressTx stops sending control packets so the peer's detection timer expires.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name,
        [ValidateRange(1, 255)][int]$DetectMult,
        [ValidateRange(1000, 4294967295)][long]$DesiredMinTxInterval,
        [ValidateRange(1000, 4294967295)][long]$RequiredMinRxInterval,
        [bool]$SuppressTx,
        [bool]$AdminDown
    )
    process {
        if (-not $script:BfdSessions.ContainsKey($Name)) { throw "No BFD session named '$Name'" }
        $s = $script:BfdSessions[$Name]
        $bound = $PSBoundParameters
        Invoke-OspfLock $s {
            if ($bound.ContainsKey('DetectMult')) { $s.DetectMult = $DetectMult }
            if ($bound.ContainsKey('DesiredMinTxInterval')) { $s.DesiredMinTx = $DesiredMinTxInterval; $s.PollPending = $true }
            if ($bound.ContainsKey('RequiredMinRxInterval')) { $s.RequiredMinRx = $RequiredMinRxInterval; $s.PollPending = $true }
            if ($bound.ContainsKey('SuppressTx')) { $s.SuppressTx = $SuppressTx }
            if ($bound.ContainsKey('AdminDown')) {
                if ($AdminDown) { Set-BfdState $s 'AdminDown' 7 'administratively down' } else { Set-BfdState $s 'Down' 0 'administratively enabled' }
            }
            $s.NextTx = [datetime]::UtcNow
        }
    }
}
