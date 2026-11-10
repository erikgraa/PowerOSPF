[CmdletBinding()]
param(
    [string] $Owner = 'erikgraa',
    [ValidateSet('users', 'orgs')] [string] $OwnerType = 'users',
    [string] $Package = 'powerospf',
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PackageApi {
    param([string] $Path, [string] $Method = 'GET')
    if (-not $env:GH_TOKEN) { throw 'GH_TOKEN is required.' }
    $response = Invoke-WebRequest -Uri "https://api.github.com$Path" -Method $Method -Headers @{
        Authorization = "Bearer $env:GH_TOKEN"
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    if ($Method -eq 'DELETE') {
        if ($response.StatusCode -ne 204) { throw 'Package deletion did not return HTTP 204.' }
        return
    }
    $content = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { $response.Content }
    $data = ConvertFrom-Json -InputObject $content -Depth 100 -NoEnumerate
    if ($Path -match '/versions\?' -and $data -isnot [array]) { throw 'Package inventory is not an array.' }
    if ($null -eq $data) { throw 'Empty API response.' }
    return $data
}

function Get-PackageVersions {
    param([string] $BasePath)
    $versions = [System.Collections.Generic.List[object]]::new()
    $ids = [System.Collections.Generic.HashSet[long]]::new()
    # Fetch an empty terminal page rather than assuming a short page is the end.
    for ($page = 1; $page -le 1000; $page++) {
        $batch = @(Invoke-PackageApi "$BasePath/versions?per_page=100&page=$page")
        if ($batch.Count -eq 0) { return ,$versions.ToArray() }
        foreach ($version in $batch) {
            if ($null -eq $version -or $version.id -isnot [long] -and $version.id -isnot [int] -or
                $version.id -le 0 -or -not $ids.Add($version.id)) { throw 'Invalid or duplicate package version ID.' }
            if ($version.name -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Invalid package digest.' }
            if ($null -eq $version.metadata.container.tags -or $version.metadata.container.tags -isnot [array]) {
                throw 'Missing container tags.'
            }
            foreach ($tag in $version.metadata.container.tags) {
                if ($tag -isnot [string] -or -not $tag) { throw 'Invalid container tag.' }
            }
            $null = [DateTimeOffset]::Parse($version.created_at, [cultureinfo]::InvariantCulture)
            $null = [DateTimeOffset]::Parse($version.updated_at, [cultureinfo]::InvariantCulture)
            $versions.Add($version)
        }
    }
    throw 'Package pagination limit reached; refusing incomplete inventory.'
}

function Get-RegistryToken {
    param([string] $Owner, [string] $Package)
    if (-not $env:GH_TOKEN) { throw 'GH_TOKEN is required.' }
    $basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${Owner}:$env:GH_TOKEN"))
    $scope = [uri]::EscapeDataString("repository:${Owner}/${Package}:pull")
    $response = Invoke-RestMethod -Uri "https://ghcr.io/token?service=ghcr.io&scope=$scope" -Headers @{ Authorization = "Basic $basic" }
    if (-not $response.token) { throw 'Registry did not return a token.' }
    return $response.token
}

function Get-RegistryManifest {
    param([string] $Owner, [string] $Package, [string] $Digest, [string] $Token)
    $response = Invoke-WebRequest -Uri "https://ghcr.io/v2/$Owner/$Package/manifests/$Digest" -Headers @{
        Authorization = "Bearer $Token"
        Accept = 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
    }
    if (@($response.Headers['Docker-Content-Digest'])[0] -ne $Digest) { throw 'Registry digest mismatch.' }
    $content = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { $response.Content }
    return ConvertFrom-Json -InputObject $content -Depth 100
}

function Get-ReferencedDigests {
    param([object[]] $Versions, [scriptblock] $ReadManifest)
    $referenced = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($version in $Versions) {
        if ($version.metadata.container.tags.Count -gt 0) { $queue.Enqueue($version.name) }
    }
    while ($queue.Count -gt 0) {
        $digest = $queue.Dequeue()
        if (-not $visited.Add($digest)) { continue }
        $manifest = & $ReadManifest $digest
        if ($manifest.schemaVersion -ne 2) { throw 'Unsupported manifest schema.' }
        $children = @()
        switch ($manifest.mediaType) {
            { $_ -in 'application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json' } {
                if ($manifest.manifests -isnot [array] -or $manifest.manifests.Count -eq 0) { throw 'Incomplete image index.' }
                $children += $manifest.manifests
            }
            { $_ -in 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json' } {
                if (-not $manifest.config.digest -or $manifest.layers -isnot [array]) { throw 'Incomplete image manifest.' }
            }
            default { throw 'Unsupported manifest media type.' }
        }
        if ($manifest.PSObject.Properties['subject']) { $children += $manifest.subject }
        foreach ($child in $children) {
            if ($child.digest -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Invalid referenced manifest digest.' }
            $null = $referenced.Add($child.digest)
            $queue.Enqueue($child.digest)
        }
    }
    return ,$referenced
}

function Test-ExpiredContainerVersion {
    param([object] $Version, [DateTimeOffset] $Now)
    $cutoff = $Now.ToUniversalTime().AddDays(-30)
    if ([DateTimeOffset]::Parse($Version.created_at) -ge $cutoff -or
        [DateTimeOffset]::Parse($Version.updated_at) -ge $cutoff) { return $false }
    $tags = @($Version.metadata.container.tags)
    if ($tags.Count -eq 0) { return $false }
    foreach ($tag in $tags) {
        if ($tag -cmatch '^sha-[a-f0-9]{7,40}$') { continue }
        if ($tag -cmatch '^nightly-(\d{8}|\d{14})$') {
            $format = if ($Matches[1].Length -eq 8) { 'yyyyMMdd' } else { 'yyyyMMddHHmmss' }
            $date = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParseExact($Matches[1], $format, [cultureinfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal, [ref] $date) -and $date -lt $cutoff) { continue }
        }
        # Any release, moving alias, unknown or recent dated tag protects the entire version.
        return $false
    }
    return $true
}

function Invoke-ContainerRetention {
    param([string] $Owner, [string] $OwnerType, [string] $Package, [switch] $Apply,
        [DateTimeOffset] $Now = [DateTimeOffset]::UtcNow)
    if ($Owner -cnotmatch '^[a-zA-Z0-9-]+$' -or $Package -cnotmatch '^[a-z0-9._-]+$') { throw 'Invalid package identity.' }
    $basePath = "/$OwnerType/$Owner/packages/container/$([uri]::EscapeDataString($Package))"
    $versions = Get-PackageVersions $basePath
    if ($versions.Count -eq 0) { Write-Host 'No package versions.'; return }
    $token = Get-RegistryToken $Owner $Package
    $referenced = Get-ReferencedDigests $versions {
        param($digest)
        Get-RegistryManifest $Owner $Package $digest $token
    }
    $candidates = @($versions | Where-Object {
        (Test-ExpiredContainerVersion $_ $Now) -and -not $referenced.Contains($_.name)
    })
    Write-Host "Inventory: $($versions.Count); eligible: $($candidates.Count); apply: $Apply"
    if ($Apply -and $candidates.Count -gt 0) {
        # Recheck the entire inventory before the first deletion, not only candidate tags.
        $fresh = Get-PackageVersions $basePath
        $snapshot = ConvertTo-Json -InputObject @($versions | Sort-Object id) -Depth 100 -Compress
        $current = ConvertTo-Json -InputObject @($fresh | Sort-Object id) -Depth 100 -Compress
        if ($snapshot -cne $current) { throw 'Package inventory changed; refusing deletion.' }
    }
    foreach ($version in $candidates) {
        Write-Host "Eligible version $($version.id): $($version.metadata.container.tags -join ', ')"
        if ($Apply) {
            $live = Invoke-PackageApi "$basePath/versions/$($version.id)"
            if ((ConvertTo-Json $live -Depth 100 -Compress) -cne (ConvertTo-Json $version -Depth 100 -Compress)) {
                throw 'Candidate changed; refusing deletion.'
            }
            Invoke-PackageApi "$basePath/versions/$($version.id)" 'DELETE'
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ContainerRetention -Owner $Owner -OwnerType $OwnerType -Package $Package -Apply:$Apply
}
