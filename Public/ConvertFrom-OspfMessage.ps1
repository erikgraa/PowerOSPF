function ConvertFrom-OspfMessage {
    <#
    .SYNOPSIS
        Parses an OSPFv2 packet (byte[]) into an object. Malformed input yields Valid=$false and an Error text instead of throwing.
    .DESCRIPTION
        Use -HasIpHeader for bytes captured from a raw socket. With -AuthKey, AuthValid reports whether
        the simple password or MD5 digest verifies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][byte[]]$Message,
        [switch]$HasIpHeader,
        [string]$AuthKey
    )
    begin { $buf = [System.Collections.Generic.List[byte]]::new() }
    process { if ($null -ne $Message) { $buf.AddRange($Message) } }
    end {
        $data = $buf.ToArray()
        try {
            if ($HasIpHeader) {
                $ihl = ($data[0] -band 0x0F) * 4
                $data = [byte[]]$data[$ihl..($data.Length - 1)]
            }
            if ($data.Length -lt 24) { throw 'Truncated OSPF header' }
            $type = [int]$data[1]
            $len = [int](Get-OspfUInt $data 2 2)
            if ($len -lt 24 -or $len -gt $data.Length) { throw "Invalid OSPF length $len (have $($data.Length) bytes)" }
            $au = [int](Get-OspfUInt $data 14 2)
            $o = [ordered]@{
                Valid          = $true
                Error          = $null
                Version        = [int]$data[0]
                Type           = $type
                TypeName       = $script:PacketTypeNames[$type]
                Length         = $len
                RouterId       = Get-OspfIp $data 4
                AreaId         = Get-OspfIp $data 8
                Checksum       = [int](Get-OspfUInt $data 12 2)
                ChecksumValid  = if ($au -eq 2) { $null } else { Test-OspfPacketChecksum $data }
                AuthType       = if ($script:AuthTypeNames.ContainsKey($au)) { $script:AuthTypeNames[$au] } else { "$au" }
                AuthValid      = $null
                KeyId          = $null
                CryptoSequence = $null
            }
            if ($au -eq 2) {
                $o.KeyId = [int]$data[18]
                $o.CryptoSequence = Get-OspfUInt $data 20 4
            }
            if ($PSBoundParameters.ContainsKey('AuthKey') -or $au -eq 0) { $o.AuthValid = Test-OspfPacketAuth -Data $data -AuthKey $AuthKey }
            switch ($type) {
                1 {
                    $o.NetworkMask = Get-OspfIp $data 24
                    $o.HelloInterval = [int](Get-OspfUInt $data 28 2)
                    $o.Options = [int]$data[30]
                    $o.Priority = [int]$data[31]
                    $o.DeadInterval = Get-OspfUInt $data 32 4
                    $o.DesignatedRouter = Get-OspfIp $data 36
                    $o.BackupDesignatedRouter = Get-OspfIp $data 40
                    $n = for ($p = 44; $p + 4 -le $len; $p += 4) { Get-OspfIp $data $p }
                    $o.Neighbors = @($n)
                }
                2 {
                    $o.InterfaceMtu = [int](Get-OspfUInt $data 24 2)
                    $o.Options = [int]$data[26]
                    $f = [int]$data[27]
                    $o.Flags = $f
                    $o.Init = [bool]($f -band 4)
                    $o.More = [bool]($f -band 2)
                    $o.Master = [bool]($f -band 1)
                    $o.Sequence = Get-OspfUInt $data 28 4
                    $h = for ($p = 32; $p + 20 -le $len; $p += 20) { Read-OspfLsaHeader $data $p }
                    $o.LsaHeaders = @($h)
                }
                3 {
                    $r = for ($p = 24; $p + 12 -le $len; $p += 12) {
                        $t = [int](Get-OspfUInt $data $p 4)
                        [pscustomobject]@{ Type = $t; TypeName = $script:LsaTypeNames[$t]; LinkStateId = (Get-OspfIp $data ($p + 4)); AdvertisingRouter = (Get-OspfIp $data ($p + 8)) }
                    }
                    $o.Requests = @($r)
                }
                4 {
                    $count = [int](Get-OspfUInt $data 24 4)
                    $lsas = [System.Collections.Generic.List[object]]::new()
                    $p = 28
                    for ($i = 0; $i -lt $count -and $p + 20 -le $len; $i++) {
                        $lsa = Read-OspfLsa $data $p
                        $lsas.Add($lsa)
                        $p += $lsa.Length
                    }
                    $o.LsaCount = $count
                    $o.Lsas = $lsas.ToArray()
                }
                5 {
                    $h = for ($p = 24; $p + 20 -le $len; $p += 20) { Read-OspfLsaHeader $data $p }
                    $o.LsaHeaders = @($h)
                }
                default { throw "Unknown OSPF packet type $type" }
            }
            $o.Bytes = $data
            [pscustomobject]$o
        }
        catch {
            [pscustomobject]@{ Valid = $false; Error = $_.Exception.Message; Bytes = $data }
        }
    }
}
