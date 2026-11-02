function Send-OspfMessage {
    <#
    .SYNOPSIS
        Sends raw bytes (an OSPF packet from New-Ospf*, or deliberately malformed bytes) from the session's socket.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(Mandatory, Position = 1)][byte[]]$Message,
        [ipaddress]$Destination = '224.0.0.5',
        [ValidateRange(1, 100000)][int]$Count = 1
    )
    $s = Get-OspfSessionState -Name $Name
    Invoke-OspfLock $s {
        for ($i = 0; $i -lt $Count; $i++) { $s.Outbox.Enqueue([pscustomobject]@{ Destination = $Destination; Bytes = $Message }) }
        Add-OspfEvent -Session $s -Direction 'Sent' -Type 'Raw' -Message "$($Message.Length) bytes x$Count to $Destination" -Bytes $Message
    }
    if ($s.Status -eq 'Running' -and $s.Socket -and -not $s.PowerShell) { Send-OspfOutbox $s }
}
