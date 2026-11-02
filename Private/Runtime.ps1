function New-OspfSocket {
    param([ipaddress]$LocalAddress)
    $s = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]89)
    try {
        $s.Bind([System.Net.IPEndPoint]::new($LocalAddress, 0))
        $ip = [System.Net.Sockets.SocketOptionLevel]::IP
        $s.SetSocketOption($ip, [System.Net.Sockets.SocketOptionName]::MulticastTimeToLive, 1)
        $s.SetSocketOption($ip, [System.Net.Sockets.SocketOptionName]::MulticastLoopback, $false)
        $s.SetSocketOption($ip, [System.Net.Sockets.SocketOptionName]::MulticastInterface, $LocalAddress.GetAddressBytes())
        $s.Ttl = 1
        foreach ($g in $script:AllSpfRouters, $script:AllDRouters) {
            $s.SetSocketOption($ip, [System.Net.Sockets.SocketOptionName]::AddMembership, [System.Net.Sockets.MulticastOption]::new($g, $LocalAddress))
        }
        try { $s.SetSocketOption($ip, [System.Net.Sockets.SocketOptionName]::TypeOfService, 0xC0) } catch { }
    }
    catch { $s.Dispose(); throw }
    $s
}

function Send-OspfOutbox {
    param($Session)
    $item = $null
    while ($Session.Outbox.TryDequeue([ref]$item)) {
        if ($Session.Socket) {
            try { $null = $Session.Socket.SendTo([byte[]]$item.Bytes, [System.Net.IPEndPoint]::new($item.Destination, 0)) }
            catch { Invoke-OspfLock $Session { Add-OspfEvent -Session $Session -Direction 'Info' -Type 'SocketError' -Message "Send failed: $($_.Exception.Message)" } }
        }
    }
}

function Invoke-OspfRuntime {
    # Runs inside a background runspace: receives packets, drives timers, drains the outbox.
    param($Session)
    $buf = [byte[]]::new(65535)
    while (-not $Session.Cancel) {
        try {
            if ($Session.Socket.Poll(50000, [System.Net.Sockets.SelectMode]::SelectRead)) {
                $ep = [System.Net.EndPoint][System.Net.IPEndPoint]::new([ipaddress]::Any, 0)
                $n = $Session.Socket.ReceiveFrom($buf, [ref]$ep)
                $data = [byte[]]$buf[0..($n - 1)]
                $src = $ep.Address
                Invoke-OspfLock $Session { Invoke-OspfReceive -Session $Session -Data $data -Source $src -HasIpHeader }
            }
            Invoke-OspfLock $Session { Invoke-OspfTick -Session $Session }
        }
        catch {
            Invoke-OspfLock $Session { Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Error' -Message $_.Exception.Message }
            Start-Sleep -Milliseconds 100
        }
        Send-OspfOutbox $Session
    }
    Send-OspfOutbox $Session
}

function Start-OspfRuntime {
    param($Session, [switch]$NoNetwork)
    $now = [datetime]::UtcNow
    Invoke-OspfLock $Session {
        $Session.Status = 'Running'
        $Session.Cancel = $false
        $Session.Neighbors = @{}
        $Session.Dr = [long]0
        $Session.Bdr = [long]0
        $Session.NextHello = $now
        if ($Session.NetworkType -eq 'PointToPoint') { $Session.InterfaceState = 'PointToPoint' }
        elseif ($Session.Priority -eq 0) { $Session.InterfaceState = 'DROther' }
        else { $Session.InterfaceState = 'Waiting'; $Session.WaitDeadline = $now.AddSeconds($Session.DeadInterval) }
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Session' -Message "Started: $($Session.InterfaceState)"
        Update-OspfOwnLsas -Session $Session -Now $now -Force
    }
    if ($NoNetwork) { return }
    try { $Session.Socket = New-OspfSocket -LocalAddress $Session.LocalAddress }
    catch {
        $Session.Status = 'Stopped'
        $Session.InterfaceState = 'Down'
        throw "Cannot open a raw IP protocol 89 socket on $($Session.LocalAddress): $($_.Exception.Message) Raw sockets need elevation (Administrator on Windows; root or CAP_NET_RAW on Linux), and the address must exist on this host."
    }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript({
            param($manifest, $state)
            Import-Module $manifest -Force
            & (Get-Module PowerOSPF) { param($s) Invoke-OspfRuntime -Session $s } $state
        }).AddArgument($script:ModuleManifest).AddArgument($Session)
    $Session.Runspace = $rs
    $Session.PowerShell = $ps
    $Session.Handle = $ps.BeginInvoke()
}

function Stop-OspfRuntime {
    param($Session, [switch]$Silent)
    Invoke-OspfLock $Session {
        if ($Session.Status -eq 'Running' -and -not $Silent) { Send-OspfPacket -Session $Session -Type 1 -Destination $script:AllSpfRouters -Info 'goodbye' `
                -Body (Get-OspfHelloBody -Mask $Session.Mask -HelloInterval $Session.HelloInterval -Options $Session.Options -Priority $Session.Priority -DeadInterval $Session.DeadInterval -Dr 0 -Bdr 0) }
    }
    $Session.Cancel = $true
    if ($Session.PowerShell) {
        try { $null = $Session.Handle.AsyncWaitHandle.WaitOne(3000); $Session.PowerShell.Stop() } catch { }
        $Session.PowerShell.Dispose()
        $Session.Runspace.Dispose()
    }
    elseif ($Session.Socket) { Send-OspfOutbox $Session }
    if ($Session.Socket) { $Session.Socket.Dispose() }
    $Session.PowerShell = $null; $Session.Runspace = $null; $Session.Handle = $null; $Session.Socket = $null
    Invoke-OspfLock $Session {
        $Session.Status = 'Stopped'
        $Session.InterfaceState = 'Down'
        $Session.Neighbors = @{}
        $Session.Dr = [long]0
        $Session.Bdr = [long]0
        $Session.Lsdb = @{}
        $Session.Originated = @{}
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Session' -Message 'Stopped'
    }
}

function Get-OspfSessionState {
    param([string]$Name, [switch]$All)
    if ($Name) {
        if (-not $script:OspfSessions.ContainsKey($Name)) { throw "No OSPF session named '$Name'" }
        return $script:OspfSessions[$Name]
    }
    @($script:OspfSessions.Values)
}
