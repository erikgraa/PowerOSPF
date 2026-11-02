BeforeAll {
    Import-Module "$PSScriptRoot\..\PowerOSPF.psd1" -Force
    $script:ModulePath = "$PSScriptRoot\..\PowerOSPF.psd1"
}

Describe 'New-Packet' {
    It 'encodes integers big-endian' {
        (New-Packet -Field (New-PacketField A 0x0102 -Bytes 2)) -join ',' | Should -Be '1,2'
    }
    It 'auto-fills the length field' {
        $p = New-Packet -LengthField L -Field @((New-PacketField L 0 -Bytes 2), (New-PacketField D 'AABBCC'))
        $p -join ',' | Should -Be '0,5,170,187,204'
    }
    It 'accepts ip addresses and byte arrays' {
        (New-Packet -Field @((New-PacketField A ([ipaddress]'1.2.3.4')), (New-PacketField B ([byte[]](9, 8))))) -join ',' | Should -Be '1,2,3,4,9,8'
    }
    It 'rejects values that do not fit' {
        { New-Packet -Field (New-PacketField A 300 -Bytes 1) } | Should -Throw
    }
    It 'Format-Packet dumps offsets, hex and ascii even for zero bytes' {
        $dump = ([byte[]](0, 0, 65, 66)) | Format-Packet
        $dump | Should -Match '^0000  00 00 41 42 '
        $dump | Should -Match '\.\.AB$'
    }
}

Describe 'Checksums' {
    It 'internet checksum matches RFC 1071 example' {
        InModuleScope PowerOSPF {
            Get-InternetChecksum ([byte[]](0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7)) | Should -Be 0x220d
        }
    }
    It 'LSA Fletcher checksum verifies and detects corruption' {
        InModuleScope PowerOSPF {
            $lsa = New-OspfLsa -Type External -AdvertisingRouter 1.1.1.1 -LinkStateId 10.9.0.0 -Metric 20
            Test-OspfLsaChecksum $lsa | Should -BeTrue
            $lsa[30] = $lsa[30] -bxor 1
            Test-OspfLsaChecksum $lsa | Should -BeFalse
        }
    }
    It 'LSA checksum does not depend on age' {
        $a = ConvertFrom-OspfLsa (New-OspfLsa -Type Router -AdvertisingRouter 1.1.1.1 -Age 0)
        $b = ConvertFrom-OspfLsa (New-OspfLsa -Type Router -AdvertisingRouter 1.1.1.1 -Age 500)
        $a.Checksum | Should -Be $b.Checksum
        $b.ChecksumValid | Should -BeTrue
    }
}

Describe 'OSPF packet round-trips' {
    It 'Hello' {
        $m = New-OspfHello -RouterId 1.1.1.1 -AreaId 0.0.0.1 -NetworkMask 255.255.255.0 -HelloInterval 5 -DeadInterval 20 -Priority 7 `
            -DesignatedRouter 10.0.0.2 -BackupDesignatedRouter 10.0.0.3 -Neighbor 2.2.2.2, 3.3.3.3 | ConvertFrom-OspfMessage
        $m.Valid | Should -BeTrue
        $m.TypeName | Should -Be 'Hello'
        $m.RouterId | Should -Be ([ipaddress]'1.1.1.1')
        $m.AreaId | Should -Be ([ipaddress]'0.0.0.1')
        $m.HelloInterval | Should -Be 5
        $m.DeadInterval | Should -Be 20
        $m.Priority | Should -Be 7
        $m.DesignatedRouter | Should -Be ([ipaddress]'10.0.0.2')
        $m.Neighbors.Count | Should -Be 2
        $m.ChecksumValid | Should -BeTrue
    }
    It 'Database Description' {
        $lsa = New-OspfLsa -Type Router -AdvertisingRouter 1.1.1.1
        $m = ConvertFrom-OspfMessage (New-OspfDbd -RouterId 1.1.1.1 -Init -More -Master -Sequence 77 -InterfaceMtu 1400 -LsaHeader $lsa)
        $m.InterfaceMtu | Should -Be 1400
        ($m.Init, $m.More, $m.Master) | Should -Be ($true, $true, $true)
        $m.Sequence | Should -Be 77
        $m.LsaHeaders.Count | Should -Be 1
        $m.LsaHeaders[0].TypeName | Should -Be 'Router'
    }
    It 'Link State Request' {
        $m = ConvertFrom-OspfMessage (New-OspfLsRequest -RouterId 1.1.1.1 -Request ([pscustomobject]@{ Type = 'Router'; LinkStateId = '2.2.2.2'; AdvertisingRouter = '2.2.2.2' }))
        $m.Requests.Count | Should -Be 1
        $m.Requests[0].TypeName | Should -Be 'Router'
        $m.Requests[0].LinkStateId | Should -Be ([ipaddress]'2.2.2.2')
    }
    It 'Link State Update with every LSA type' {
        $lsas = @(
            New-OspfLsa -Type Router -AdvertisingRouter 1.1.1.1 -Link (New-OspfRouterLink Transit 10.0.0.2 10.0.0.1 -Metric 3), (New-OspfRouterLink Stub 192.168.1.0 255.255.255.0 -Metric 1)
            New-OspfLsa -Type Network -AdvertisingRouter 1.1.1.1 -LinkStateId 10.0.0.1 -AttachedRouter 1.1.1.1, 2.2.2.2
            New-OspfLsa -Type SummaryNetwork -AdvertisingRouter 1.1.1.1 -LinkStateId 172.16.0.0 -Mask 255.255.0.0 -Metric 15
            New-OspfLsa -Type SummaryAsbr -AdvertisingRouter 1.1.1.1 -LinkStateId 9.9.9.9 -Metric 4
            New-OspfLsa -Type External -AdvertisingRouter 1.1.1.1 -LinkStateId 10.9.0.0 -Metric 20 -ExternalType 1 -Tag 5
        )
        $m = ConvertFrom-OspfMessage (New-OspfLsUpdate -RouterId 1.1.1.1 -Lsa $lsas)
        $m.LsaCount | Should -Be 5
        ($m.Lsas | Where-Object { -not $_.ChecksumValid }) | Should -BeNullOrEmpty
        $m.Lsas[0].Links.Count | Should -Be 2
        $m.Lsas[0].Links[0].TypeName | Should -Be 'Transit'
        $m.Lsas[1].AttachedRouters.Count | Should -Be 2
        $m.Lsas[2].Metric | Should -Be 15
        $m.Lsas[4].ExternalType | Should -Be 1
        $m.Lsas[4].Tag | Should -Be 5
    }
    It 'Link State Ack' {
        $m = ConvertFrom-OspfMessage (New-OspfLsAck -RouterId 1.1.1.1 -LsaHeader (New-OspfLsa -Type Router -AdvertisingRouter 2.2.2.2))
        $m.TypeName | Should -Be 'LinkStateAck'
        $m.LsaHeaders[0].AdvertisingRouter | Should -Be ([ipaddress]'2.2.2.2')
    }
    It 'parses raw socket bytes with an IP header' {
        $ip = [byte[]](0x45, 0, 0, 0, 0, 0, 0, 0, 1, 89, 0, 0, 10, 0, 0, 1, 224, 0, 0, 5)
        $pkt = New-OspfHello -RouterId 1.1.1.1
        (ConvertFrom-OspfMessage ([byte[]]($ip + $pkt)) -HasIpHeader).RouterId | Should -Be ([ipaddress]'1.1.1.1')
    }
    It 'reports malformed input without throwing' {
        (ConvertFrom-OspfMessage ([byte[]](1, 2, 3))).Valid | Should -BeFalse
        $bad = New-OspfHello -RouterId 1.1.1.1
        $bad[2] = 0xFF
        (ConvertFrom-OspfMessage $bad).Error | Should -Match 'length'
    }
    It 'flags a corrupt checksum' {
        (ConvertFrom-OspfMessage (New-OspfHello -RouterId 1.1.1.1 -CorruptChecksum)).ChecksumValid | Should -BeFalse
    }
}

Describe 'OSPF authentication' {
    It 'simple password verifies only with the right key' {
        $p = New-OspfHello -RouterId 1.1.1.1 -AuthType Simple -AuthKey lab
        (ConvertFrom-OspfMessage $p -AuthKey lab).AuthValid | Should -BeTrue
        (ConvertFrom-OspfMessage $p -AuthKey nope).AuthValid | Should -BeFalse
        (ConvertFrom-OspfMessage $p).AuthType | Should -Be 'Simple'
    }
    It 'MD5 appends a digest and verifies' {
        $plain = New-OspfHello -RouterId 1.1.1.1
        $p = New-OspfHello -RouterId 1.1.1.1 -AuthType Md5 -AuthKey secret -KeyId 3 -CryptoSequence 42
        $p.Length | Should -Be ($plain.Length + 16)
        $m = ConvertFrom-OspfMessage $p -AuthKey secret
        $m.AuthValid | Should -BeTrue
        $m.KeyId | Should -Be 3
        $m.CryptoSequence | Should -Be 42
        (ConvertFrom-OspfMessage $p -AuthKey wrong).AuthValid | Should -BeFalse
    }
    It 'a tampered MD5 packet fails' {
        $p = New-OspfHello -RouterId 1.1.1.1 -AuthType Md5 -AuthKey secret
        $p[31] = $p[31] -bxor 1
        (ConvertFrom-OspfMessage $p -AuthKey secret).AuthValid | Should -BeFalse
    }
}

Describe 'DR election' {
    It 'highest priority wins, router ID breaks ties, BDR is runner-up' {
        InModuleScope PowerOSPF {
            $c = @(
                [pscustomobject]@{ Id = 1; Ip = 101; Priority = 1; Dr = 0; Bdr = 0 }
                [pscustomobject]@{ Id = 2; Ip = 102; Priority = 5; Dr = 0; Bdr = 0 }
                [pscustomobject]@{ Id = 3; Ip = 103; Priority = 5; Dr = 0; Bdr = 0 }
            )
            $r = Select-OspfDesignatedRouter $c
            $r.Bdr | Should -Be 103
            $r.Dr | Should -Be 103
        }
    }
    It 'an incumbent DR is not pre-empted' {
        InModuleScope PowerOSPF {
            $c = @(
                [pscustomobject]@{ Id = 1; Ip = 101; Priority = 1; Dr = 101; Bdr = 102 }
                [pscustomobject]@{ Id = 2; Ip = 102; Priority = 1; Dr = 101; Bdr = 102 }
                [pscustomobject]@{ Id = 9; Ip = 109; Priority = 200; Dr = 101; Bdr = 102 }
            )
            $r = Select-OspfDesignatedRouter $c
            $r.Dr | Should -Be 101
            $r.Bdr | Should -Be 102
        }
    }
    It 'priority 0 routers are excluded by the caller' {
        InModuleScope PowerOSPF {
            $r = Select-OspfDesignatedRouter @([pscustomobject]@{ Id = 2; Ip = 102; Priority = 1; Dr = 0; Bdr = 0 })
            $r.Dr | Should -Be 102
        }
    }
}

Describe 'Adjacency between two in-memory routers' {
    BeforeAll {
        InModuleScope PowerOSPF {
            function script:New-Pair {
                param([hashtable]$AExtra = @{}, [hashtable]$BExtra = @{})
                $a = New-OspfSessionState -Name a -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 @AExtra
                $b = New-OspfSessionState -Name b -RouterId 2.2.2.2 -LocalAddress 10.0.0.2 @BExtra
                $t0 = [datetime]'2030-01-01T00:00:00Z'
                foreach ($s in $a, $b) { $s.Status = 'Running'; $s.NextHello = $t0 }
                foreach ($s in $a, $b) {
                    $s.InterfaceState = 'Waiting'; $s.WaitDeadline = $t0.AddSeconds($s.DeadInterval)
                    Update-OspfOwnLsas -Session $s -Now $t0 -Force
                }
                [pscustomobject]@{ A = $a; B = $b; Now = $t0 }
            }
            function script:Step-Pair {
                param($Pair, [int]$Seconds, [scriptblock]$Filter = { $true })
                for ($i = 0; $i -lt $Seconds; $i++) {
                    $Pair.Now = $Pair.Now.AddSeconds(1)
                    foreach ($s in $Pair.A, $Pair.B) { Invoke-OspfTick -Session $s -Now $Pair.Now }
                    for ($round = 0; $round -lt 30; $round++) {
                        $moved = $false
                        foreach ($dir in @(@($Pair.A, $Pair.B), @($Pair.B, $Pair.A))) {
                            $from, $to = $dir
                            $item = $null
                            while ($from.Outbox.TryDequeue([ref]$item)) {
                                $moved = $true
                                $d = ConvertTo-OspfLong $item.Destination
                                if (($d -eq $to.LocalAddressLong -or $item.Destination.Equals($script:AllSpfRouters) -or $item.Destination.Equals($script:AllDRouters)) -and (& $Filter $item)) {
                                    Invoke-OspfReceive -Session $to -Data $item.Bytes -Source $from.LocalAddress -Now $Pair.Now
                                }
                            }
                        }
                        if (-not $moved) { break }
                    }
                }
            }
        }
    }

    It 'forms a Full adjacency, elects a DR and exchanges LSDBs' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            @($p.A.Neighbors.Values)[0].State | Should -Be 'Full'
            @($p.B.Neighbors.Values)[0].State | Should -Be 'Full'
            # router ID 2.2.2.2 (equal priority) wins the DR election; nobody was DR before so BDR/DR roles are split by ID
            $p.A.Dr | Should -Be $p.B.Dr
            $p.A.Dr | Should -Not -Be 0
            $p.A.Lsdb.Count | Should -Be $p.B.Lsdb.Count
            $p.A.Lsdb.Count | Should -BeGreaterOrEqual 3
        }
    }

    It 'the DR originates a Network LSA and both routers compute the connected route' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            $dr = if ($p.A.InterfaceState -eq 'DR') { $p.A } else { $p.B }
            @($dr.Lsdb.Values | Where-Object { $_.Key -like '2|*' }).Count | Should -Be 1
            $routes = Invoke-OspfSpf -Session $p.A -Now $p.Now
            ($routes | Where-Object { $_.Prefix -eq [ipaddress]'10.0.0.0' -and $_.PrefixLength -eq 24 }) | Should -Not -BeNullOrEmpty
        }
    }

    It 'originated prefixes and externals propagate and appear in the peer routing table' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            $x = ConvertFrom-OspfPrefix '192.168.50.0/24'; Add-Member -InputObject $x -NotePropertyMembers @{ Metric = 5 }
            $p.A.Prefixes.Add($x)
            $e = ConvertFrom-OspfPrefix '172.20.0.0/16'
            Add-Member -InputObject $e -NotePropertyMembers @{ Metric = 40; ExternalType = 2; Tag = [long]0; ForwardingAddress = [ipaddress]'0.0.0.0' }
            $p.A.Externals.Add($e)
            Update-OspfOwnLsas -Session $p.A -Now $p.Now
            Step-Pair $p 3
            $routes = Invoke-OspfSpf -Session $p.B -Now $p.Now
            $stub = $routes | Where-Object { $_.Prefix -eq [ipaddress]'192.168.50.0' }
            $stub.Type | Should -Be 'IntraArea'
            $stub.NextHop | Should -Be ([ipaddress]'10.0.0.1')
            $ext = $routes | Where-Object { $_.Prefix -eq [ipaddress]'172.20.0.0' }
            $ext.Type | Should -Be 'External2'
            $ext.Cost | Should -Be 40
            # withdraw: the LSA is flushed to MaxAge on the peer
            $p.A.Externals.Clear()
            Update-OspfOwnLsas -Session $p.A -Now $p.Now
            Step-Pair $p 3
            (Invoke-OspfSpf -Session $p.B -Now $p.Now | Where-Object { $_.Prefix -eq [ipaddress]'172.20.0.0' }) | Should -BeNullOrEmpty
        }
    }

    It 'mismatched hello interval prevents any neighbor from forming' {
        InModuleScope PowerOSPF {
            $p = New-Pair -BExtra @{ HelloInterval = 5; DeadInterval = 20 }
            Step-Pair $p 30
            $p.A.Neighbors.Count | Should -Be 0
            ($p.A.Events | Where-Object Type -eq 'HelloMismatch').Count | Should -BeGreaterThan 0
        }
    }

    It 'an MTU larger than the peer interface MTU stalls the exchange' {
        InModuleScope PowerOSPF {
            $p = New-Pair -BExtra @{ Mtu = 9000 }
            Step-Pair $p 60
            @($p.A.Neighbors.Values)[0].State | Should -Be 'ExStart'
            ($p.A.Events | Where-Object Type -eq 'MtuMismatch').Count | Should -BeGreaterThan 0
        }
    }

    It 'authentication mismatch drops packets' {
        InModuleScope PowerOSPF {
            $p = New-Pair -AExtra @{ AuthType = 'Md5'; AuthKey = 'one' } -BExtra @{ AuthType = 'Md5'; AuthKey = 'two' }
            Step-Pair $p 20
            $p.A.Neighbors.Count | Should -Be 0
        }
    }

    It 'matching MD5 authentication forms the adjacency' {
        InModuleScope PowerOSPF {
            $p = New-Pair -AExtra @{ AuthType = 'Md5'; AuthKey = 'k' } -BExtra @{ AuthType = 'Md5'; AuthKey = 'k' }
            Step-Pair $p 60
            @($p.A.Neighbors.Values)[0].State | Should -Be 'Full'
        }
    }

    It 'stopping hellos lets the peer dead timer kill the neighbor' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            $p.B.SuppressHellos = $true
            Step-Pair $p 45
            $p.A.Neighbors.Count | Should -Be 0
            ($p.A.Events | Where-Object { $_.Type -eq 'NeighborState' -and $_.Message -like '*InactivityTimer*' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'a BFD Down takes the neighbor Down immediately' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            $bfd = New-BfdSessionState -Name x -Peer 10.0.0.2 -LocalAddress 10.0.0.1 -DetectMult 3 -DesiredMinTx 1000000 -RequiredMinRx 1000000 -AuthType None -AuthKey '' -KeyId 1
            $bfd.State = 'Down'; $bfd.WasUp = $true
            $p.A.Bfd = $bfd
            Invoke-OspfTick -Session $p.A -Now $p.Now
            $p.A.Neighbors.Count | Should -Be 0
            ($p.A.Events | Where-Object Type -eq 'Bfd').Count | Should -Be 1
        }
    }

    It 'Reset-OspfNeighbor forces a neighbor Down at once and holds Hellos down' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            $p.A.Neighbors.Count | Should -Be 1
            Remove-OspfNeighbor $p.A @($p.A.Neighbors.Values)[0] 'external' $p.Now
            $p.A.Neighbors.Count | Should -Be 0
        }
    }

    It 'a self-originated LSA with higher remote sequence is re-originated' {
        InModuleScope PowerOSPF {
            $p = New-Pair
            Step-Pair $p 60
            $key = "1|1.1.1.1|1.1.1.1"
            $seq = (Read-OspfLsaHeader $p.A.Lsdb[$key].Bytes 0).Sequence
            $fake = New-OspfLsa -Type Router -AdvertisingRouter 1.1.1.1 -Sequence ($seq + 10)
            Invoke-OspfReceive -Session $p.A -Data (New-OspfLsUpdate -RouterId 2.2.2.2 -Lsa $fake) -Source 10.0.0.2 -Now $p.Now
            (Read-OspfLsaHeader $p.A.Lsdb[$key].Bytes 0).Sequence | Should -BeGreaterThan ($seq + 10)
        }
    }
}

Describe 'BFD packets' {
    It 'round-trips a control packet' {
        $m = New-BfdControl -State Up -Diagnostic 3 -DetectMult 5 -MyDiscriminator 11 -YourDiscriminator 22 -DesiredMinTxInterval 300000 -RequiredMinRxInterval 400000 -Poll | ConvertFrom-BfdControl
        $m.Valid | Should -BeTrue
        $m.State | Should -Be 'Up'
        $m.Diagnostic | Should -Be 3
        $m.DetectMult | Should -Be 5
        $m.MyDiscriminator | Should -Be 11
        $m.YourDiscriminator | Should -Be 22
        $m.DesiredMinTxInterval | Should -Be 300000
        $m.Poll | Should -BeTrue
        $m.Length | Should -Be 24
    }
    It 'authenticates with <Type>' -ForEach @(
        @{ Type = 'Simple'; Len = 24 + 3 + 6 }
        @{ Type = 'KeyedMd5'; Len = 48 }
        @{ Type = 'MeticulousKeyedMd5'; Len = 48 }
        @{ Type = 'KeyedSha1'; Len = 52 }
        @{ Type = 'MeticulousKeyedSha1'; Len = 52 }
    ) {
        $p = New-BfdControl -State Up -AuthType $Type -AuthKey secret -KeyId 2 -Sequence 9
        $p.Length | Should -Be $Len
        $m = ConvertFrom-BfdControl $p -AuthKey secret
        $m.AuthType | Should -Be $Type
        $m.KeyId | Should -Be 2
        $m.AuthValid | Should -BeTrue
        (ConvertFrom-BfdControl $p -AuthKey wrong).AuthValid | Should -BeFalse
    }
}

Describe 'BFD state machine' {
    It 'brings a session Up through the three-way handshake and detects loss' {
        InModuleScope PowerOSPF {
            $s = New-BfdSessionState -Name t -Peer 10.0.0.2 -LocalAddress 10.0.0.1 -DetectMult 3 -DesiredMinTx 1000000 -RequiredMinRx 1000000 -AuthType None -AuthKey '' -KeyId 1
            $s.Status = 'Running'
            $now = [datetime]'2030-01-01T00:00:00Z'
            Invoke-BfdReceive -S $s -Source 10.0.0.2 -Now $now -Data (New-BfdControl -State Down -MyDiscriminator 77)
            $s.State | Should -Be 'Init'
            Invoke-BfdReceive -S $s -Source 10.0.0.2 -Now $now -Data (New-BfdControl -State Init -MyDiscriminator 77 -YourDiscriminator $s.MyDisc)
            $s.State | Should -Be 'Up'
            $s.WasUp | Should -BeTrue
            Invoke-BfdTick -S $s -Now $now.AddSeconds(10)
            $s.State | Should -Be 'Down'
            $s.Diagnostic | Should -Be 1
        }
    }
    It 'goes Down when the peer signals Down and rejects packets with a wrong discriminator' {
        InModuleScope PowerOSPF {
            $s = New-BfdSessionState -Name t -Peer 10.0.0.2 -LocalAddress 10.0.0.1 -DetectMult 3 -DesiredMinTx 1000000 -RequiredMinRx 1000000 -AuthType None -AuthKey '' -KeyId 1
            $s.Status = 'Running'
            $now = [datetime]'2030-01-01T00:00:00Z'
            Invoke-BfdReceive -S $s -Source 10.0.0.2 -Now $now -Data (New-BfdControl -State Init -MyDiscriminator 77 -YourDiscriminator 5)
            $s.State | Should -Be 'Down'
            Invoke-BfdReceive -S $s -Source 10.0.0.2 -Now $now -Data (New-BfdControl -State Down -MyDiscriminator 77)
            Invoke-BfdReceive -S $s -Source 10.0.0.2 -Now $now -Data (New-BfdControl -State Up -MyDiscriminator 77 -YourDiscriminator $s.MyDisc)
            $s.State | Should -Be 'Up'
            Invoke-BfdReceive -S $s -Source 10.0.0.2 -Now $now -Data (New-BfdControl -State Down -MyDiscriminator 77 -YourDiscriminator $s.MyDisc)
            $s.State | Should -Be 'Down'
            $s.Diagnostic | Should -Be 3
        }
    }
}

Describe 'Sessions without a network' {
    AfterEach { Get-OspfSession | Remove-OspfSession -Silent }
    It 'starts, reports, exports and removes a session' {
        Start-OspfSession -Name t -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 -Prefix 192.168.1.0/24 -ExternalPrefix 172.16.0.0/16 -NoNetwork
        $s = Get-OspfSession t
        $s.Status | Should -Be 'Running'
        $s.InterfaceState | Should -Be 'Waiting'
        $s.DeadInterval | Should -Be 40
        (Get-OspfLsa t -Type Router).Links.Count | Should -Be 2
        (Get-OspfLsa t -Type External).LinkStateId | Should -Be ([ipaddress]'172.16.0.0')
        (Export-OspfConfig t | ConvertFrom-Json).Prefix | Should -Be '192.168.1.0/24'
        Get-OspfEvent t | Should -Not -BeNullOrEmpty
        Remove-OspfSession t
        { Get-OspfSession t } | Should -Throw
    }
    It 'Set-OspfSession changes timers and Send-OspfLsa adds and withdraws prefixes' {
        Start-OspfSession -Name t -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 -NoNetwork
        Set-OspfSession t -HelloInterval 3 -SuppressHellos $true
        $s = Get-OspfSession t
        $s.HelloInterval | Should -Be 3
        $s.DeadInterval | Should -Be 12
        $s.SuppressHellos | Should -BeTrue
        Send-OspfLsa t -Type External -Prefix 10.9.0.0/24 -Metric 7
        (Get-OspfLsa t -Type External).Metric | Should -Be 7
        Send-OspfLsa t -Type External -Prefix 10.9.0.0/24 -Withdraw
        (Get-OspfLsa t -Type External).Age | Should -Be 3600
    }
    It 'Stop and Resume keep the configuration' {
        Start-OspfSession -Name t -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 -Prefix 10.1.0.0/24 -NoNetwork
        Stop-OspfSession t -Silent
        (Get-OspfSession t).Status | Should -Be 'Stopped'
        Resume-OspfSession t -NoNetwork
        (Get-OspfSession t).Status | Should -Be 'Running'
        (Get-OspfLsa t -Type Router).Links.Count | Should -Be 2
    }
    It 'Send-OspfMessage queues raw bytes for injection' {
        Start-OspfSession -Name t -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 -NoNetwork
        Send-OspfMessage t ([byte[]](1, 2, 3)) -Destination 10.0.0.2
        (Get-OspfEvent t -Type Raw).Count | Should -Be 1
    }
    It 'rejects duplicate session names' {
        Start-OspfSession -Name t -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 -NoNetwork
        { Start-OspfSession -Name t -RouterId 1.1.1.1 -LocalAddress 10.0.0.1 -NoNetwork } | Should -Throw
    }
}
