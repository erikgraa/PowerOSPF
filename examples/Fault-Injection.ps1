# Fault-injection walkthrough against a live neighbor. Run elevated.
Import-Module "$PSScriptRoot\..\PowerOSPF.psd1" -Force
Start-OspfSession -Name lab -RouterId 10.0.0.9 -LocalAddress 10.0.0.9
while (-not (Get-OspfNeighbor lab | Where-Object State -eq 'Full')) { Start-Sleep 1 }

# 1. Silent death: the peer's dead timer expires
Set-OspfSession lab -SuppressHellos $true
Start-Sleep 50
Get-OspfNeighbor lab
Set-OspfSession lab -SuppressHellos $false

# 2. Timer mismatch: Hellos are rejected by the peer
Set-OspfSession lab -HelloInterval 3 -DeadInterval 7
Start-Sleep 20
Set-OspfSession lab -HelloInterval 10 -DeadInterval 40

# 3. MTU mismatch: the adjacency sticks in ExStart
Set-OspfSession lab -Mtu 9000
Update-OspfSession lab -ResetNeighbors
Start-Sleep 20
Get-OspfNeighbor lab
Set-OspfSession lab -Mtu 1500

# 4. Malformed packet
$bad = New-OspfHello -RouterId 10.0.0.9 -CorruptChecksum
Send-OspfMessage lab $bad

Remove-OspfSession lab
