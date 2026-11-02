function Start-BfdSession {
    <#
    .SYNOPSIS
        Starts a single-hop BFD session (UDP 3784, TTL 255) with a peer.
    .DESCRIPTION
        Binds UDP port 3784 on -LocalAddress (one BFD session per local address). Pass the session name to
        Start-OspfSession -BfdSession so that BFD Down immediately takes the OSPF neighbor Down.
    .EXAMPLE
        Start-BfdSession -Name bfd1 -Peer 10.0.0.1 -LocalAddress 10.0.0.9
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ipaddress]$Peer,
        [Parameter(Mandatory)][ipaddress]$LocalAddress,
        [ValidateRange(1, 255)][int]$DetectMult = 3,
        [ValidateRange(1000, 4294967295)][long]$DesiredMinTxInterval = 1000000,
        [ValidateRange(1000, 4294967295)][long]$RequiredMinRxInterval = 1000000,
        [ValidateSet('None', 'Simple', 'KeyedMd5', 'MeticulousKeyedMd5', 'KeyedSha1', 'MeticulousKeyedSha1')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [ValidateRange(0, 255)][int]$KeyId = 1,
        [switch]$NoNetwork,
        [switch]$PassThru
    )
    if ($script:BfdSessions.ContainsKey($Name)) { throw "A BFD session named '$Name' already exists" }
    if ($AuthType -ne 'None' -and -not $AuthKey) { throw "-AuthKey is required for AuthType $AuthType" }
    $s = New-BfdSessionState -Name $Name -Peer $Peer -LocalAddress $LocalAddress -DetectMult $DetectMult -DesiredMinTx $DesiredMinTxInterval -RequiredMinRx $RequiredMinRxInterval `
        -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId
    Start-BfdRuntime -S $s -NoNetwork:$NoNetwork
    $script:BfdSessions[$Name] = $s
    if ($PassThru) { Get-BfdSession -Name $Name }
}
