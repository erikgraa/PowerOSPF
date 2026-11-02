function ConvertFrom-OspfLsa {
    <#
    .SYNOPSIS
        Parses one LSA (byte[], header at offset 0) into an object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][byte[]]$Lsa)
    Read-OspfLsa -Data $Lsa -Offset 0
}
