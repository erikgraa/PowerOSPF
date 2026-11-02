function New-BfdControl {
    <#
    .SYNOPSIS
        Builds a BFD control packet (RFC 5880) as byte[]; intervals are in microseconds.
    .EXAMPLE
        New-BfdControl -State Up -MyDiscriminator 1 -YourDiscriminator 2 -AuthType MeticulousKeyedSha1 -AuthKey secret -Sequence 7
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('AdminDown', 'Down', 'Init', 'Up')][string]$State = 'Down',
        [ValidateRange(0, 31)][int]$Diagnostic = 0,
        [ValidateRange(0, 255)][int]$DetectMult = 3,
        [long]$MyDiscriminator = 1,
        [long]$YourDiscriminator = 0,
        [long]$DesiredMinTxInterval = 1000000,
        [long]$RequiredMinRxInterval = 1000000,
        [long]$RequiredMinEchoRxInterval = 0,
        [switch]$Poll,
        [switch]$Final,
        [switch]$ControlPlaneIndependent,
        [switch]$Demand,
        [switch]$Multipoint,
        [ValidateSet('None', 'Simple', 'KeyedMd5', 'MeticulousKeyedMd5', 'KeyedSha1', 'MeticulousKeyedSha1')][string]$AuthType = 'None',
        [string]$AuthKey = '',
        [ValidateRange(0, 255)][int]$KeyId = 1,
        [long]$Sequence = 0
    )
    New-BfdPacketBytes -State $script:BfdStateNumbers[$State] -Diagnostic $Diagnostic -DetectMult $DetectMult -MyDiscriminator $MyDiscriminator -YourDiscriminator $YourDiscriminator `
        -DesiredMinTx $DesiredMinTxInterval -RequiredMinRx $RequiredMinRxInterval -RequiredMinEchoRx $RequiredMinEchoRxInterval `
        -Poll ([bool]$Poll) -Final ([bool]$Final) -ControlPlaneIndependent ([bool]$ControlPlaneIndependent) -Demand ([bool]$Demand) -Multipoint ([bool]$Multipoint) `
        -AuthType $AuthType -AuthKey $AuthKey -KeyId $KeyId -Sequence $Sequence
}
