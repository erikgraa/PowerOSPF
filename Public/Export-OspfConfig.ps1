function Export-OspfConfig {
    <#
    .SYNOPSIS
        Exports a session's configuration as JSON (and optionally to a file). Auth keys are omitted unless -IncludeSecrets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$Path,
        [switch]$IncludeSecrets
    )
    $s = Get-OspfSessionState -Name $Name
    $cfg = Invoke-OspfLock $s {
        [ordered]@{
            Name           = $s.Name
            RouterId       = "$($s.RouterId)"
            LocalAddress   = "$($s.LocalAddress)"
            PrefixLength   = $s.PrefixLength
            AreaId         = "$($s.AreaId)"
            NetworkType    = $s.NetworkType
            HelloInterval  = $s.HelloInterval
            DeadInterval   = $s.DeadInterval
            Priority       = $s.Priority
            Cost           = $s.Cost
            Mtu            = $s.Mtu
            InterfaceMtu   = $s.InterfaceMtu
            Options        = $s.Options
            AuthType       = $s.AuthType
            KeyId          = $s.KeyId
            AuthKey        = $(if ($IncludeSecrets) { $s.AuthKey } else { $null })
            Prefix         = @($s.Prefixes | ForEach-Object { "$($_.Network)/$($_.PrefixLength)" })
            ExternalPrefix = @($s.Externals | ForEach-Object { "$($_.Network)/$($_.PrefixLength)" })
            SummaryPrefix  = @($s.Summaries | ForEach-Object { "$($_.Network)/$($_.PrefixLength)" })
        }
    }
    $json = $cfg | ConvertTo-Json -Depth 4
    if ($Path) { Set-Content -Path $Path -Value $json }
    $json
}
