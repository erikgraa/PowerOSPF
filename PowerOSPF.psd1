@{
    RootModule           = 'PowerOSPF.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '3b8e1d52-7c4a-4f0e-9a63-5d2f8c1b6e07'
    Author               = 'erikgraa'
    Description          = 'Lab-use-only tool to stand up OSPFv2 test routers from PowerShell against routers such as Cisco, MikroTik, FRR or NSX. Form adjacencies over raw IP protocol 89, originate LSAs and prefixes, inject faults, and build or parse OSPF packets with a generic packet builder.'
    CompanyName          = 'erikgraa'
    Copyright            = '(c) erikgraa. All rights reserved.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'New-PacketField', 'New-Packet', 'Format-Packet',
        'New-OspfHello', 'New-OspfDbd', 'New-OspfLsRequest', 'New-OspfLsUpdate', 'New-OspfLsAck',
        'New-OspfLsa', 'New-OspfRouterLink', 'ConvertFrom-OspfMessage', 'ConvertFrom-OspfLsa',
        'Start-OspfSession', 'Get-OspfSession', 'Set-OspfSession', 'Update-OspfSession',
        'Stop-OspfSession', 'Resume-OspfSession', 'Remove-OspfSession',
        'Get-OspfNeighbor', 'Get-OspfLsa', 'Get-OspfRoute', 'Send-OspfLsa', 'Send-OspfMessage',
        'Get-OspfEvent', 'Export-OspfConfig', 'Reset-OspfNeighbor'

    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('OSPF', 'OSPFv2', 'Routing', 'Lab', 'Testing', 'Networking', 'Packet')
            LicenseUri = 'https://github.com/erikgraa/PowerOSPF/blob/main/LICENSE'
            ProjectUri = 'https://github.com/erikgraa/PowerOSPF'
        }
    }
}
