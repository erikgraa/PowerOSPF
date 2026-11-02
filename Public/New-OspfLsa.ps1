function New-OspfLsa {
    <#
    .SYNOPSIS
        Builds a complete LSA (header + body, Fletcher checksum filled in) as byte[].
    .EXAMPLE
        New-OspfLsa -Type External -AdvertisingRouter 1.1.1.1 -LinkStateId 10.9.0.0 -Mask 255.255.255.0 -Metric 20
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Router', 'Network', 'SummaryNetwork', 'SummaryAsbr', 'External')][string]$Type,
        [Parameter(Mandatory)][ipaddress]$AdvertisingRouter,
        [ipaddress]$LinkStateId,
        [long]$Sequence = 2147483649,
        [ValidateRange(0, 3600)][int]$Age = 0,
        [ValidateRange(0, 255)][int]$Options = 2,
        [object[]]$Link = @(),
        [ValidateRange(0, 255)][int]$Flags = 0,
        [ipaddress]$Mask = '255.255.255.0',
        [ipaddress[]]$AttachedRouter = @(),
        [ValidateRange(0, 16777215)][int]$Metric = 10,
        [ValidateSet(1, 2)][int]$ExternalType = 2,
        [ipaddress]$ForwardingAddress = '0.0.0.0',
        [long]$Tag = 0
    )
    if (-not $LinkStateId) {
        if ($Type -eq 'Router') { $LinkStateId = $AdvertisingRouter } else { throw '-LinkStateId is required for this LSA type' }
    }
    $body = [System.Collections.Generic.List[byte]]::new()
    switch ($Type) {
        'Router' {
            $body.Add([byte]$Flags); $body.Add(0)
            $body.AddRange([byte[]](ConvertTo-OspfBytes $Link.Count 2))
            foreach ($l in $Link) {
                $body.AddRange([byte[]]$l.LinkId.GetAddressBytes())
                $body.AddRange([byte[]]$l.LinkData.GetAddressBytes())
                $body.Add([byte]$l.Type); $body.Add(0)
                $body.AddRange([byte[]](ConvertTo-OspfBytes $l.Metric 2))
            }
        }
        'Network' {
            $body.AddRange([byte[]]$Mask.GetAddressBytes())
            foreach ($r in $AttachedRouter) { $body.AddRange([byte[]]$r.GetAddressBytes()) }
        }
        { $_ -in 'SummaryNetwork', 'SummaryAsbr' } {
            $body.AddRange([byte[]]$Mask.GetAddressBytes())
            $body.AddRange([byte[]](ConvertTo-OspfBytes $Metric 4))
        }
        'External' {
            $body.AddRange([byte[]]$Mask.GetAddressBytes())
            $e = if ($ExternalType -eq 2) { [long]2147483648 } else { 0 }
            $body.AddRange([byte[]](ConvertTo-OspfBytes ([long]$e + $Metric) 4))
            $body.AddRange([byte[]]$ForwardingAddress.GetAddressBytes())
            $body.AddRange([byte[]](ConvertTo-OspfBytes $Tag 4))
        }
    }
    $lsa = [byte[]](Join-OspfBytes (ConvertTo-OspfBytes $Age 2) (ConvertTo-OspfBytes $Options 1) (ConvertTo-OspfBytes $script:LsaTypeNumbers[$Type] 1) `
            $LinkStateId.GetAddressBytes() $AdvertisingRouter.GetAddressBytes() (ConvertTo-OspfBytes $Sequence 4) (ConvertTo-OspfBytes 0 2) `
            (ConvertTo-OspfBytes (20 + $body.Count) 2) $body.ToArray())
    Set-OspfLsaChecksum $lsa
    , $lsa
}
