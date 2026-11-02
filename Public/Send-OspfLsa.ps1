function Send-OspfLsa {
    <#
    .SYNOPSIS
        Originates, withdraws or injects LSAs in a session.
    .DESCRIPTION
        -Prefix with -Type Router adds a stub link to the session's Router LSA; -Type External or SummaryNetwork
        originates a Type 5 or Type 3 LSA. -Withdraw removes the prefix again (the LSA is flushed with MaxAge).
        -Lsa installs an arbitrary LSA (byte[] from New-OspfLsa, even one that spoofs another router) and floods it.
    .EXAMPLE
        Send-OspfLsa lab -Type External -Prefix 10.9.0.0/24 -Metric 20 -ExternalType 1
        Send-OspfLsa lab -Type External -Prefix 10.9.0.0/24 -Withdraw
    #>
    [CmdletBinding(DefaultParameterSetName = 'Prefix')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(ParameterSetName = 'Prefix')][ValidateSet('Router', 'External', 'SummaryNetwork')][string]$Type = 'External',
        [Parameter(Mandatory, ParameterSetName = 'Prefix')][string[]]$Prefix,
        [Parameter(ParameterSetName = 'Prefix')][ValidateRange(0, 16777215)][int]$Metric = 10,
        [Parameter(ParameterSetName = 'Prefix')][ValidateSet(1, 2)][int]$ExternalType = 2,
        [Parameter(ParameterSetName = 'Prefix')][long]$Tag = 0,
        [Parameter(ParameterSetName = 'Prefix')][ipaddress]$ForwardingAddress = '0.0.0.0',
        [Parameter(ParameterSetName = 'Prefix')][switch]$Withdraw,
        [Parameter(Mandatory, ParameterSetName = 'Raw')]$Lsa
    )
    $s = Get-OspfSessionState -Name $Name
    $setName = $PSCmdlet.ParameterSetName
    Invoke-OspfLock $s {
        $now = [datetime]::UtcNow
        if ($s.Status -ne 'Running') { throw "Session '$Name' is not running" }
        if ($setName -eq 'Raw') {
            foreach ($l in (ConvertTo-OspfByteList $Lsa)) {
                $key = Install-OspfLsa $s $l $now
                Add-OspfEvent -Session $s -Direction 'Info' -Type 'Inject' -Message "Injected LSA $key"
                Send-OspfFlood $s @($key) $now
            }
            return
        }
        $list = @{ Router = $s.Prefixes; External = $s.Externals; SummaryNetwork = $s.Summaries }[$Type]
        foreach ($p in $Prefix) {
            $x = ConvertFrom-OspfPrefix $p
            $existing = @($list | Where-Object { $_.Network.Equals($x.Network) -and $_.PrefixLength -eq $x.PrefixLength })
            foreach ($e in $existing) { $null = $list.Remove($e) }
            if ($Withdraw) { continue }
            Add-Member -InputObject $x -NotePropertyMembers @{ Metric = $Metric; ExternalType = $ExternalType; Tag = $Tag; ForwardingAddress = $ForwardingAddress }
            $list.Add($x)
        }
        Update-OspfOwnLsas -Session $s -Now $now
    }
}
