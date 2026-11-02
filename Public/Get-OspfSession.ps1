function Get-OspfSession {
    <#
    .SYNOPSIS
        Lists OSPF sessions with interface state, DR/BDR and neighbor/LSDB counts.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Name)
    $list = if ($Name) { @(Get-OspfSessionState -Name $Name) } else { @(Get-OspfSessionState) }
    foreach ($s in $list) {
        Invoke-OspfLock $s {
            [pscustomobject]@{
                PSTypeName     = 'PowerOSPF.Session'
                Name           = $s.Name
                Status         = $s.Status
                RouterId       = $s.RouterId
                LocalAddress   = $s.LocalAddress
                PrefixLength   = $s.PrefixLength
                AreaId         = $s.AreaId
                NetworkType    = $s.NetworkType
                InterfaceState = $s.InterfaceState
                DesignatedRouter       = ConvertFrom-OspfLong $s.Dr
                BackupDesignatedRouter = ConvertFrom-OspfLong $s.Bdr
                HelloInterval  = $s.HelloInterval
                DeadInterval   = $s.DeadInterval
                Priority       = $s.Priority
                Cost           = $s.Cost
                Mtu            = $s.Mtu
                AuthType       = $s.AuthType
                SuppressHellos = [bool]$s.SuppressHellos
                Neighbors      = $s.Neighbors.Count
                FullNeighbors  = @($s.Neighbors.Values | Where-Object { $_.State -eq 'Full' }).Count
                LsdbCount      = $s.Lsdb.Count
            }
        }
    }
}
