[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\out')
)
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "PowerOSPF-$([guid]::NewGuid().ToString('N'))"
$module = Join-Path $stage 'PowerOSPF'
New-Item -ItemType Directory -Path $module, $OutputPath -Force | Out-Null
try {
    foreach ($item in 'PowerOSPF.psd1', 'PowerOSPF.psm1', 'Public', 'Private', 'LICENSE', 'README.md', 'CHANGELOG.md', 'icon.png') {
        Copy-Item -Path (Join-Path $root $item) -Destination $module -Recurse
    }
    Test-ModuleManifest -Path (Join-Path $module 'PowerOSPF.psd1') | Out-Null
    Compress-PSResource -Path $module -DestinationPath (Resolve-Path $OutputPath) -SkipModuleManifestValidate
    Get-ChildItem $OutputPath -Filter '*.nupkg'
}
finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
