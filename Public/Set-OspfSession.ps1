function Set-OspfSession {
    <#
    .SYNOPSIS
        Changes a running session; ideal for fault injection (mismatched timers/MTU, suppressed hellos, bad checksums, auth).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][string]$Name,
        [ValidateRange(1, 65535)][int]$HelloInterval,
        [ValidateRange(1, 4294967295)][long]$DeadInterval,
        [ValidateRange(0, 255)][int]$Priority,
        [ValidateRange(1, 65535)][int]$Cost,
        [ValidateRange(0, 65535)][int]$Mtu,
        [ValidateRange(68, 65535)][int]$InterfaceMtu,
        [ValidateRange(0, 255)][int]$Options,
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType,
        [string]$AuthKey,
        [ValidateRange(0, 255)][int]$KeyId,
        [bool]$SuppressHellos,
        [bool]$CorruptChecksum,
        [switch]$PassThru
    )
    process {
        $s = Get-OspfSessionState -Name $Name
        $bound = $PSBoundParameters
        Invoke-OspfLock $s {
            $now = [datetime]::UtcNow
            foreach ($k in 'HelloInterval', 'DeadInterval', 'Cost', 'Mtu', 'InterfaceMtu', 'Options', 'AuthType', 'AuthKey', 'KeyId', 'SuppressHellos', 'CorruptChecksum') {
                if ($bound.ContainsKey($k)) { $s[$k] = $bound[$k] }
            }
            if ($bound.ContainsKey('HelloInterval') -and -not $bound.ContainsKey('DeadInterval')) { $s.DeadInterval = 4 * $HelloInterval }
            if ($bound.ContainsKey('Priority')) {
                $s.Priority = $Priority
                if ($s.Status -eq 'Running') { Invoke-OspfElection $s $now }
            }
            if ($bound.ContainsKey('Cost')) { $s.LsaDirty = $true }
            $s.NextHello = $now
            Add-OspfEvent -Session $s -Direction 'Info' -Type 'Config' -Message "Set: $(($bound.Keys | Where-Object { $_ -notin 'Name', 'PassThru' }) -join ', ')"
            if ($s.LsaDirty) { Update-OspfOwnLsas -Session $s -Now $now }
        }
        if ($PassThru) { Get-OspfSession -Name $Name }
    }
}
