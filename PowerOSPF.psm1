$script:ModuleRoot = $PSScriptRoot
$script:ModuleManifest = Join-Path $PSScriptRoot 'PowerOSPF.psd1'
$script:OspfSessions = @{}

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    . $file.FullName
}

Export-ModuleMember -Function $public.BaseName
