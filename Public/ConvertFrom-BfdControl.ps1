function ConvertFrom-BfdControl {
    <#
    .SYNOPSIS
        Parses a BFD control packet (byte[], UDP payload). With -AuthKey, AuthValid reports whether the authentication verifies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][byte[]]$Packet,
        [string]$AuthKey
    )
    begin { $buf = [System.Collections.Generic.List[byte]]::new() }
    process { if ($null -ne $Packet) { $buf.AddRange($Packet) } }
    end {
        $d = $buf.ToArray()
        try {
            if ($d.Length -lt 24) { throw 'Truncated BFD control packet' }
            $len = [int]$d[3]
            if ($len -lt 24 -or $len -gt $d.Length) { throw "Invalid BFD length $len" }
            $flags = [int]$d[1]
            $o = [ordered]@{
                Valid                     = $true
                Error                     = $null
                Version                   = [int]($d[0] -shr 5)
                Diagnostic                = [int]($d[0] -band 0x1F)
                State                     = $script:BfdStateNames[[int]($d[1] -shr 6)]
                Poll                      = [bool]($flags -band 0x20)
                Final                     = [bool]($flags -band 0x10)
                ControlPlaneIndependent   = [bool]($flags -band 0x08)
                AuthPresent               = [bool]($flags -band 0x04)
                Demand                    = [bool]($flags -band 0x02)
                Multipoint                = [bool]($flags -band 0x01)
                DetectMult                = [int]$d[2]
                Length                    = $len
                MyDiscriminator           = Get-OspfUInt $d 4 4
                YourDiscriminator         = Get-OspfUInt $d 8 4
                DesiredMinTxInterval      = Get-OspfUInt $d 12 4
                RequiredMinRxInterval     = Get-OspfUInt $d 16 4
                RequiredMinEchoRxInterval = Get-OspfUInt $d 20 4
                AuthType                  = 'None'
                KeyId                     = $null
                Sequence                  = $null
                AuthValid                 = $null
            }
            if ($o.AuthPresent) {
                if ($len -lt 26) { throw 'Truncated BFD authentication section' }
                $au = [int]$d[24]
                $o.AuthType = if ($script:BfdAuthNames.ContainsKey($au)) { $script:BfdAuthNames[$au] } else { "$au" }
                $o.KeyId = [int]$d[26]
                if ($au -ge 2 -and $len -ge 32) { $o.Sequence = Get-OspfUInt $d 28 4 }
                if ($PSBoundParameters.ContainsKey('AuthKey')) { $o.AuthValid = Test-BfdAuth -Data $d -AuthKey $AuthKey }
            }
            $o.Bytes = $d
            [pscustomobject]$o
        }
        catch { [pscustomobject]@{ Valid = $false; Error = $_.Exception.Message; Bytes = $d } }
    }
}
