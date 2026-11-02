# Run elevated (Administrator / root): OSPF needs a raw IP protocol 89 socket.
Import-Module "$PSScriptRoot\..\PowerOSPF.psd1" -Force

Start-OspfSession -Name lab -RouterId 10.0.0.9 -LocalAddress 10.0.0.9 -PrefixLength 24 `
    -Prefix 192.168.9.0/24 -ExternalPrefix 172.31.0.0/16

# Wait for Full
while (-not (Get-OspfNeighbor lab | Where-Object State -eq 'Full')) { Start-Sleep 1 }

Get-OspfNeighbor lab | Format-Table
Get-OspfLsa lab | Format-Table Type, TypeName, LinkStateId, AdvertisingRouter, Age, SequenceHex
Get-OspfRoute lab | Format-Table

Send-OspfLsa lab -Type External -Prefix 10.99.0.0/24 -Metric 20 -ExternalType 1
Start-Sleep 5
Send-OspfLsa lab -Type External -Prefix 10.99.0.0/24 -Withdraw

Remove-OspfSession lab
