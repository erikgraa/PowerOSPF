function Invoke-OspfReceive {
    param(
        $Session,
        [byte[]]$Data,
        [ipaddress]$Source,
        [switch]$HasIpHeader,
        [datetime]$Now = [datetime]::UtcNow
    )
    if ($Session.Status -ne 'Running') { return }
    $srcLong = ConvertTo-OspfLong $Source
    if ($srcLong -eq $Session.LocalAddressLong) { return }
    $authKey = if ($Session.AuthType -ne 'None') { $Session.AuthKey } else { '' }
    $msg = ConvertFrom-OspfMessage -Message $Data -HasIpHeader:$HasIpHeader -AuthKey $authKey
    if (-not $msg.Valid) {
        Add-OspfEvent -Session $Session -Direction 'Received' -Type 'Invalid' -Message "Dropped from ${Source}: $($msg.Error)" -Bytes $msg.Bytes
        return
    }
    $drop = {
        param($why)
        Add-OspfEvent -Session $Session -Direction 'Received' -Type $msg.TypeName -Message "Dropped from ${Source}: $why" -Neighbor $msg.RouterId.ToString() -Bytes $msg.Bytes
    }
    if ($msg.Version -ne 2) { & $drop "version $($msg.Version)"; return }
    if ($msg.RouterId.Equals($Session.RouterId)) { return }
    if (-not $msg.AreaId.Equals($Session.AreaId)) { & $drop "area mismatch ($($msg.AreaId))"; return }
    if ($msg.AuthType -ne $Session.AuthType) { & $drop "auth type mismatch ($($msg.AuthType))"; return }
    if ($msg.AuthType -eq 'Md5') {
        if (-not $msg.AuthValid) { & $drop 'MD5 digest invalid'; return }
    }
    else {
        if (-not $msg.ChecksumValid) { & $drop 'bad checksum'; return }
        if ($msg.AuthType -eq 'Simple' -and -not $msg.AuthValid) { & $drop 'simple password mismatch'; return }
    }
    $key = $msg.RouterId.ToString()
    $n = $Session.Neighbors[$key]
    if ($msg.AuthType -eq 'Md5' -and $n) {
        if ($msg.CryptoSequence -lt $n.LastCrypto) { & $drop 'MD5 sequence replay'; return }
        $n.LastCrypto = $msg.CryptoSequence
    }
    Add-OspfEvent -Session $Session -Direction 'Received' -Type $msg.TypeName -Message "from $Source" -Neighbor $key -Bytes $msg.Bytes

    if ($msg.Type -eq 1) { Receive-OspfHello $Session $msg $srcLong $Now }
    elseif ($null -eq $n) { & $drop 'unknown neighbor' }
    else {
        $n.Deadline = $Now.AddSeconds($Session.DeadInterval)
        switch ($msg.Type) {
            2 { Receive-OspfDbd $Session $n $msg $Now }
            3 { Receive-OspfLsr $Session $n $msg $Now }
            4 { Receive-OspfLsu $Session $n $msg $Now }
            5 { Receive-OspfLsAck $Session $n $msg }
        }
    }
    if ($Session.LsaDirty) { Update-OspfOwnLsas -Session $Session -Now $Now }
}

function Receive-OspfHello {
    param($Session, $Msg, [long]$SrcLong, [datetime]$Now)
    $why = $null
    if ($Session.NetworkType -eq 'Broadcast' -and -not $Msg.NetworkMask.Equals($Session.Mask)) { $why = "network mask mismatch ($($Msg.NetworkMask))" }
    elseif ($Msg.HelloInterval -ne $Session.HelloInterval) { $why = "hello interval mismatch ($($Msg.HelloInterval))" }
    elseif ($Msg.DeadInterval -ne $Session.DeadInterval) { $why = "dead interval mismatch ($($Msg.DeadInterval))" }
    elseif (($Msg.Options -band 2) -ne ($Session.Options -band 2)) { $why = "E-bit mismatch (options $($Msg.Options))" }
    if ($why) {
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'HelloMismatch' -Neighbor $Msg.RouterId.ToString() -Message "Hello rejected: $why"
        return
    }
    $key = $Msg.RouterId.ToString()
    if ($Session.HoldDown[$key] -and $Now -lt $Session.HoldDown[$key]) { return }
    $n = $Session.Neighbors[$key]
    if (-not $n) {
        $n = New-OspfNeighbor (ConvertTo-OspfLong $Msg.RouterId) $SrcLong $Now
        $Session.Neighbors[$key] = $n
    }
    $oldPrio = $n.Priority; $oldDr = $n.Dr; $oldBdr = $n.Bdr
    $n.Address = $SrcLong
    $n.Priority = $Msg.Priority
    $n.Dr = ConvertTo-OspfLong $Msg.DesignatedRouter
    $n.Bdr = ConvertTo-OspfLong $Msg.BackupDesignatedRouter
    $n.Options = $Msg.Options
    $n.Deadline = $Now.AddSeconds($Session.DeadInterval)
    if ($n.State -eq 'Down') { Set-OspfNeighborState $Session $n 'Init' 'HelloReceived' $Now }
    $seen = $false
    foreach ($x in $Msg.Neighbors) { if ($x.Equals($Session.RouterId)) { $seen = $true } }
    $elect = $false
    if ($seen) {
        if ($n.State -eq 'Init') { Set-OspfNeighborState $Session $n '2-Way' '2-WayReceived' $Now; $elect = $true }
    }
    elseif ($script:NeighborRank[$n.State] -ge 2) {
        Set-OspfNeighborState $Session $n 'Init' '1-WayReceived' $Now
        $elect = $true
    }
    if ($oldPrio -ne $n.Priority -or $oldDr -ne $n.Dr -or $oldBdr -ne $n.Bdr) { $elect = $true }
    $declared = ($n.Dr -eq $n.Address -and $n.Bdr -eq 0) -or $n.Bdr -eq $n.Address
    if ($Session.InterfaceState -eq 'Waiting') { $elect = $declared }
    if ($elect) { Invoke-OspfElection $Session $Now }
    else { Update-OspfAdjacencies $Session $Now }
}

function Receive-OspfDbd {
    param($Session, $N, $Msg, [datetime]$Now)
    if ($script:NeighborRank[$N.State] -lt $script:NeighborRank['ExStart']) {
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Dbd' -Neighbor $N.RouterId.ToString() -Message "DBD ignored in state $($N.State)"
        return
    }
    if ($Msg.InterfaceMtu -gt $Session.InterfaceMtu) {
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'MtuMismatch' -Neighbor $N.RouterId.ToString() -Message "DBD rejected: neighbor MTU $($Msg.InterfaceMtu) > interface MTU $($Session.InterfaceMtu)"
        return
    }
    $recv = @{ Flags = $Msg.Flags; Options = $Msg.Options; Sequence = $Msg.Sequence }
    $same = $N.LastRecv -and $N.LastRecv.Flags -eq $recv.Flags -and $N.LastRecv.Options -eq $recv.Options -and $N.LastRecv.Sequence -eq $recv.Sequence

    if ($N.State -eq 'ExStart') {
        if ($Msg.Init -and $Msg.More -and $Msg.Master -and $Msg.LsaHeaders.Count -eq 0 -and $N.RouterIdLong -gt $Session.RouterIdLong) {
            $N.IsMaster = $false
            $N.DdSeq = $Msg.Sequence
            $N.Options = $Msg.Options
            $N.LastRecv = $recv
            Set-OspfNeighborState $Session $N 'Exchange' 'NegotiationDone (slave)' $Now
            Send-OspfDbdChunk $Session $N $Now
            if (-not $N.LastDbdMore -and -not $Msg.More) { Complete-OspfExchange $Session $N $Now }
            return
        }
        elseif (-not $Msg.Init -and -not $Msg.Master -and $Msg.Sequence -eq $N.DdSeq -and $N.RouterIdLong -lt $Session.RouterIdLong) {
            $N.IsMaster = $true
            $N.Options = $Msg.Options
            Set-OspfNeighborState $Session $N 'Exchange' 'NegotiationDone (master)' $Now
            $same = $false
        }
        else { return }
    }
    elseif ($same) {
        if (-not $N.IsMaster -and $N.LastDbdBody) {
            Send-OspfDbdPacket $Session $N $N.LastDbdBody $Now 'retransmit'
        }
        return
    }
    elseif ($N.State -ne 'Exchange') {
        Restart-OspfAdjacency $Session $N 'SeqNumberMismatch (DBD in Loading/Full)' $Now
        return
    }

    if ($same) {
        if (-not $N.IsMaster -and $N.LastDbdBody) { Send-OspfDbdPacket $Session $N $N.LastDbdBody $Now 'retransmit' }
        return
    }
    $expectedSeq = if ($N.IsMaster) { $N.DdSeq } else { $N.DdSeq + 1 }
    if ($Msg.Master -eq $N.IsMaster -or $Msg.Init -or $Msg.Options -ne $N.Options -or $Msg.Sequence -ne $expectedSeq) {
        Restart-OspfAdjacency $Session $N 'SeqNumberMismatch' $Now
        return
    }
    $N.LastRecv = $recv
    foreach ($h in $Msg.LsaHeaders) {
        if ($h.Type -lt 1 -or $h.Type -gt 5) { Restart-OspfAdjacency $Session $N "bad LSA type $($h.Type) in DBD" $Now; return }
        $e = $Session.Lsdb[$h.Key]
        $needed = $true
        if ($e) { $needed = (Compare-OspfLsaInstance $h (Get-OspfEntryHeader $e $Now)) -gt 0 }
        if ($needed) { $N.RequestList[$h.Key] = $h }
    }
    if ($N.IsMaster) {
        $sentMore = $N.LastDbdMore
        $N.DdSeq++
        if (-not $sentMore -and -not $Msg.More) { Complete-OspfExchange $Session $N $Now }
        else { Send-OspfDbdChunk $Session $N $Now }
    }
    else {
        $N.DdSeq = $Msg.Sequence
        Send-OspfDbdChunk $Session $N $Now
        if (-not $N.LastDbdMore -and -not $Msg.More) { Complete-OspfExchange $Session $N $Now }
    }
}

function Receive-OspfLsr {
    param($Session, $N, $Msg, [datetime]$Now)
    if ($script:NeighborRank[$N.State] -lt $script:NeighborRank['Exchange']) { return }
    $lsas = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($r in $Msg.Requests) {
        $k = "$($r.Type)|$($r.LinkStateId)|$($r.AdvertisingRouter)"
        $e = $Session.Lsdb[$k]
        if (-not $e) { Restart-OspfAdjacency $Session $N "BadLSReq for $k" $Now; return }
        $lsas.Add([byte[]](Get-OspfEntryBytes $e $Now 1))
    }
    if ($lsas.Count -gt 0) { Send-OspfLsuTo $Session $N $lsas.ToArray() }
}

function Receive-OspfLsu {
    param($Session, $N, $Msg, [datetime]$Now)
    if ($script:NeighborRank[$N.State] -lt $script:NeighborRank['Exchange']) { return }
    $acks = [System.Collections.Generic.List[byte[]]]::new()
    $flood = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $Msg.Lsas) {
        if (-not $l.ChecksumValid) {
            Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Lsa' -Neighbor $N.RouterId.ToString() -Message "LSA $($l.Key) dropped: bad checksum"
            continue
        }
        if ($l.Type -lt 1 -or $l.Type -gt 5) { continue }
        $e = $Session.Lsdb[$l.Key]
        $cmp = if ($e) { Compare-OspfLsaInstance $l (Get-OspfEntryHeader $e $Now) } else { 1 }
        $hdr = [byte[]]$l.Bytes[0..19]
        if ($cmp -gt 0) {
            if ($l.AdvertisingRouter.Equals($Session.RouterId)) {
                if ($Session.Originated.ContainsKey($l.Key)) {
                    Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Lsa' -Message "Received newer copy of own LSA $($l.Key); advancing sequence"
                    $Session.SeqFloor[$l.Key] = $l.Sequence
                    $Session.LsaDirty = $true
                    $Session.ForceOriginate = $true
                }
                else {
                    Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Lsa' -Message "Received stale own LSA $($l.Key); flushing"
                    $null = Install-OspfLsa $Session $l.Bytes $Now
                    Stop-OspfLsaInstance $Session $l.Key $Now
                }
                $acks.Add($hdr)
                continue
            }
            $others = @($Session.Neighbors.Values | Where-Object { $_.State -in 'Exchange', 'Loading' })
            if ($l.Age -ge $script:OspfMaxAge -and -not $e -and $others.Count -eq 0) { $acks.Add($hdr); continue }
            $null = Install-OspfLsa $Session $l.Bytes $Now
            $acks.Add($hdr)
            $flood.Add($l.Key)
            $N.Retrans.Remove($l.Key)
            if ($N.RequestList.ContainsKey($l.Key)) { $N.RequestList.Remove($l.Key) }
        }
        elseif ($cmp -eq 0) {
            if ($N.Retrans.ContainsKey($l.Key)) { $N.Retrans.Remove($l.Key) } else { $acks.Add($hdr) }
            if ($N.RequestList.ContainsKey($l.Key)) { $N.RequestList.Remove($l.Key) }
        }
        else {
            if ($N.RequestList.ContainsKey($l.Key)) { continue }
            Send-OspfLsuTo $Session $N @(, [byte[]](Get-OspfEntryBytes $e $Now 1))
        }
    }
    if ($acks.Count -gt 0) { Send-OspfAck $Session $N $acks.ToArray() }
    if ($flood.Count -gt 0) { Send-OspfFlood $Session $flood.ToArray() $Now $N }
    if ($N.State -eq 'Loading') {
        if ($N.RequestList.Count -eq 0) { Set-OspfNeighborState $Session $N 'Full' 'LoadingDone' $Now }
        else { Send-OspfLsrTo $Session $N $Now }
    }
}

function Receive-OspfLsAck {
    param($Session, $N, $Msg)
    foreach ($h in $Msg.LsaHeaders) {
        $r = $N.Retrans[$h.Key]
        if ($r -and $r.Sequence -eq $h.Sequence) { $N.Retrans.Remove($h.Key) }
    }
}

function Stop-OspfLsaInstance {
    # Premature aging: flood a MaxAge copy of an installed LSA.
    param($Session, [string]$Key, [datetime]$Now)
    $e = $Session.Lsdb[$Key]
    if (-not $e) { return }
    $e.Age0 = $script:OspfMaxAge
    $e.InstallTime = $Now
    $e.Originated = $false
    $Session.Originated.Remove($Key)
    Send-OspfFlood $Session @($Key) $Now
}

function Invoke-OspfTick {
    param($Session, [datetime]$Now = [datetime]::UtcNow)
    if ($Session.Status -ne 'Running') { return }
    if ($Session.Bfd -and $Session.Bfd.State -eq 'Down' -and $Session.Bfd.WasUp) {
        foreach ($n in @($Session.Neighbors.Values)) {
            if ($n.Address -eq (ConvertTo-OspfLong $Session.Bfd.Peer) -and $n.State -ne 'Down') {
                Add-OspfEvent -Session $Session -Direction 'Info' -Type 'Bfd' -Neighbor $n.RouterId.ToString() -Message 'BFD session Down: killing neighbor'
                Remove-OspfNeighbor $Session $n 'BFD Down' $Now
            }
        }
        $Session.Bfd.WasUp = $false
    }
    if ($Session.InterfaceState -eq 'Waiting' -and $Now -ge $Session.WaitDeadline) {
        Add-OspfEvent -Session $Session -Direction 'Info' -Type 'WaitTimer' -Message 'Wait timer expired'
        Invoke-OspfElection $Session $Now
    }
    foreach ($n in @($Session.Neighbors.Values)) {
        if ($Now -ge $n.Deadline) { Remove-OspfNeighbor $Session $n 'InactivityTimer' $Now }
    }
    if ($Now -ge $Session.NextHello) {
        if (-not $Session.SuppressHellos) { Send-OspfHello $Session }
        $Session.NextHello = $Now.AddSeconds($Session.HelloInterval)
    }
    $rx = $Session.RxmtInterval
    foreach ($n in @($Session.Neighbors.Values)) {
        if ($n.State -eq 'ExStart' -and ($Now - $n.LastDbdTime).TotalSeconds -ge $rx) { Send-OspfInitialDbd $Session $n $Now }
        elseif ($n.State -eq 'Exchange' -and $n.IsMaster -and $n.LastDbdBody -and ($Now - $n.LastDbdTime).TotalSeconds -ge $rx) {
            Send-OspfDbdPacket $Session $n $n.LastDbdBody $Now 'retransmit'
        }
        elseif ($n.State -eq 'Loading' -and ($Now - $n.LastLsrTime).TotalSeconds -ge $rx) { Send-OspfLsrTo $Session $n $Now }
        $due = @($n.Retrans.Keys | Where-Object { ($Now - $n.Retrans[$_].Time).TotalSeconds -ge $rx })
        if ($due.Count -gt 0) {
            $lsas = [System.Collections.Generic.List[byte[]]]::new()
            foreach ($k in $due) {
                $e = $Session.Lsdb[$k]
                if ($e) { $n.Retrans[$k].Time = $Now; $lsas.Add([byte[]](Get-OspfEntryBytes $e $Now 1)) } else { $n.Retrans.Remove($k) }
            }
            if ($lsas.Count -gt 0) { Send-OspfLsuTo $Session $n $lsas.ToArray() }
        }
    }
    if (($Now - $Session.LastRefresh).TotalSeconds -ge 1800) { $Session.ForceOriginate = $true; $Session.LsaDirty = $true }
    foreach ($k in @($Session.Lsdb.Keys)) {
        $e = $Session.Lsdb[$k]
        if ((Get-OspfLsaAge $e $Now) -ge $script:OspfMaxAge -and ($Now - $e.InstallTime).TotalSeconds -ge 10) {
            $held = @($Session.Neighbors.Values | Where-Object { $_.Retrans.ContainsKey($k) })
            if ($held.Count -eq 0) { $Session.Lsdb.Remove($k) }
        }
    }
    if ($Session.LsaDirty) { Update-OspfOwnLsas -Session $Session -Now $Now }
}

function Remove-OspfNeighbor {
    param($Session, $Neighbor, [string]$Reason, [datetime]$Now)
    $wasRank = $script:NeighborRank[$Neighbor.State]
    Set-OspfNeighborState $Session $Neighbor 'Down' $Reason $Now
    $Session.Neighbors.Remove($Neighbor.RouterId.ToString())
    if ($Session.NetworkType -eq 'Broadcast' -and $wasRank -ge 2) {
        if ($Neighbor.Address -eq $Session.Dr) { $Session.Dr = [long]0 }
        if ($Neighbor.Address -eq $Session.Bdr) { $Session.Bdr = [long]0 }
        Invoke-OspfElection $Session $Now
    }
    $Session.LsaDirty = $true
}
