function Start-OspfSession {
    <#
    .SYNOPSIS
        Starts an OSPFv2 test router on one interface address and begins forming adjacencies.
    .DESCRIPTION
        Opens a raw IP protocol 89 socket bound to -LocalAddress (requires elevation: Administrator on Windows,
        root or CAP_NET_RAW on Linux) and runs the protocol in a background runspace.
        Use -NoNetwork to build the session without a socket (useful for tests and for inspecting what would be sent).
    .EXAMPLE
        Start-OspfSession -Name lab -RouterId 10.0.0.9 -LocalAddress 10.0.0.9 -PrefixLength 24 -Prefix 192.168.9.0/24
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ipaddress]$RouterId,
        [Parameter(Mandatory)][ipaddress]$LocalAddress,
        [ValidateRange(1, 32)][int]$PrefixLength = 24,
        [ipaddress]$AreaId = '0.0.0.0',
        [ValidateSet('Broadcast', 'PointToPoint')][string]$NetworkType = 'Broadcast',
        [ValidateRange(1, 65535)][int]$HelloInterval = 10,
        [ValidateRange(1, 4294967295)][long]$DeadInterval,
        [ValidateRange(0, 255)][int]$Priority = 1,
        [ValidateRange(1, 65535)][int]$Cost = 10,
        [ValidateRange(68, 65535)][int]$Mtu = 1500,
        [ValidateRange(68, 65535)][int]$InterfaceMtu = 1500,
        [ValidateRange(0, 255)][int]$Options = 2,
        [ValidateSet('None', 'Simple', 'Md5')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [ValidateRange(0, 255)][int]$KeyId = 1,
        [string[]]$Prefix = @(),
        [string[]]$ExternalPrefix = @(),
        [string[]]$SummaryPrefix = @(),
        [ValidateRange(0, 16777215)][int]$Metric = 10,
        [string]$BfdSession,
        [switch]$NoNetwork,
        [switch]$PassThru
    )
    if ($script:OspfSessions.ContainsKey($Name)) { throw "An OSPF session named '$Name' already exists" }
    if ($AuthType -eq 'Simple' -and $AuthKey.Length -gt 8) { throw 'Simple passwords are at most 8 characters' }
    if ($AuthType -ne 'None' -and -not $AuthKey) { throw "-AuthKey is required for AuthType $AuthType" }
    if (-not $PSBoundParameters.ContainsKey('DeadInterval')) { $DeadInterval = 4 * $HelloInterval }
    $state = New-OspfSessionState -Name $Name -RouterId $RouterId -LocalAddress $LocalAddress -PrefixLength $PrefixLength -AreaId $AreaId -NetworkType $NetworkType `
        -HelloInterval $HelloInterval -DeadInterval $DeadInterval -Priority $Priority -Cost $Cost -Mtu $Mtu -InterfaceMtu $InterfaceMtu -Options $Options `
        -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId
    foreach ($p in $Prefix) { $x = ConvertFrom-OspfPrefix $p; Add-Member -InputObject $x -NotePropertyMembers @{ Metric = $Metric }; $state.Prefixes.Add($x) }
    foreach ($p in $ExternalPrefix) {
        $x = ConvertFrom-OspfPrefix $p
        Add-Member -InputObject $x -NotePropertyMembers @{ Metric = $Metric; ExternalType = 2; Tag = [long]0; ForwardingAddress = [ipaddress]'0.0.0.0' }
        $state.Externals.Add($x)
    }
    foreach ($p in $SummaryPrefix) { $x = ConvertFrom-OspfPrefix $p; Add-Member -InputObject $x -NotePropertyMembers @{ Metric = $Metric }; $state.Summaries.Add($x) }
    if ($BfdSession) {
        if (-not $script:BfdSessions.ContainsKey($BfdSession)) { throw "No BFD session named '$BfdSession'" }
        $state.Bfd = $script:BfdSessions[$BfdSession]
    }
    Start-OspfRuntime -Session $state -NoNetwork:$NoNetwork
    $script:OspfSessions[$Name] = $state
    if ($PassThru) { Get-OspfSession -Name $Name }
}
