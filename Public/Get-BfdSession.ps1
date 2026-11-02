function Get-BfdSession {
    <#
    .SYNOPSIS
        Lists BFD sessions with state, diagnostics and negotiated values.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Name)
    $list = if ($Name) { if (-not $script:BfdSessions.ContainsKey($Name)) { throw "No BFD session named '$Name'" }; @($script:BfdSessions[$Name]) } else { @($script:BfdSessions.Values) }
    foreach ($s in $list) {
        Invoke-OspfLock $s {
            [pscustomobject]@{
                PSTypeName            = 'PowerOSPF.BfdSession'
                Name                  = $s.Name
                Status                = $s.Status
                Peer                  = $s.Peer
                LocalAddress          = $s.LocalAddress
                State                 = $s.State
                RemoteState           = $s.RemoteState
                Diagnostic            = $s.Diagnostic
                LocalDiscriminator    = $s.MyDisc
                RemoteDiscriminator   = $s.YourDisc
                DetectMult            = $s.DetectMult
                DesiredMinTxInterval  = $s.DesiredMinTx
                RequiredMinRxInterval = $s.RequiredMinRx
                AuthType              = $s.AuthType
                SuppressTx            = [bool]$s.SuppressTx
            }
        }
    }
}
