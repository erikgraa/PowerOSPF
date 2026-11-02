function Format-Packet {
    <#
    .SYNOPSIS
        Hex dump of a byte[] (offset, hex, ASCII) for comparison with Wireshark.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][byte[]]$Packet,
        [ValidateRange(4, 64)][int]$Width = 16
    )
    begin { $buf = [System.Collections.Generic.List[byte]]::new() }
    process { if ($null -ne $Packet) { $buf.AddRange($Packet) } }
    end {
        $data = $buf.ToArray()
        for ($o = 0; $o -lt $data.Length; $o += $Width) {
            $n = [math]::Min($Width, $data.Length - $o)
            $chunk = $data[$o..($o + $n - 1)]
            $hex = ($chunk | ForEach-Object { $_.ToString('x2') }) -join ' '
            $asc = -join ($chunk | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
            '{0:x4}  {1}  {2}' -f $o, $hex.PadRight($Width * 3 - 1), $asc
        }
    }
}
