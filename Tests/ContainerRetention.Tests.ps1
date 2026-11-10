BeforeAll {
    . "$PSScriptRoot\..\tools\Remove-OldContainerVersion.ps1"
    function New-Version {
        param([int] $Id = 1, [string[]] $Tags = @('sha-abcdef1234567'),
            [string] $Created = '2026-09-01T00:00:00Z', [string] $Updated = '2026-09-01T00:00:00Z')
        [pscustomobject]@{
            id = $Id
            name = 'sha256:' + $Id.ToString('x').PadLeft(64, '0')
            created_at = $Created
            updated_at = $Updated
            metadata = [pscustomobject]@{ container = [pscustomobject]@{ tags = $Tags } }
        }
    }
    function New-Manifest {
        [pscustomobject]@{
            schemaVersion = 2
            mediaType = 'application/vnd.oci.image.manifest.v1+json'
            config = @{ digest = 'sha256:' + ('f' * 64) }
            layers = @()
        }
    }
    $script:Now = [DateTimeOffset]'2026-11-10T00:00:00Z'
}

Describe 'Container age and tag policy' {
    It 'expires an old SHA version' {
        Test-ExpiredContainerVersion (New-Version) $Now | Should -BeTrue
    }
    It 'expires old dated tags together with SHA tags' {
        Test-ExpiredContainerVersion (New-Version -Tags @('nightly-20260901', 'nightly-20260901031500', 'sha-abcdef1')) $Now | Should -BeTrue
    }
    It 'preserves any protected or unknown tag: <Tag>' -ForEach @(
        @{ Tag = 'latest' }, @{ Tag = 'nightly' }, @{ Tag = 'dispatch' },
        @{ Tag = '0.1.1' }, @{ Tag = '0.1' }, @{ Tag = 'v0.1.1' },
        @{ Tag = 'release-candidate' }, @{ Tag = 'SHA-abcdef1' }, @{ Tag = 'sha-bad' },
        @{ Tag = 'nightly-20260230' }, @{ Tag = 'nightly-20261109' }, @{ Tag = 'nightly-20271201' }
    ) {
        Test-ExpiredContainerVersion (New-Version -Tags @('sha-abcdef1', $Tag)) $Now | Should -BeFalse
    }
    It 'never deletes an untagged version' {
        Test-ExpiredContainerVersion (New-Version -Tags @()) $Now | Should -BeFalse
    }
    It 'protects a newly created version with an old dated tag' {
        Test-ExpiredContainerVersion (New-Version -Tags @('nightly-20260901') -Created '2026-11-09T00:00:00Z') $Now | Should -BeFalse
    }
    It 'protects recently retagged versions' {
        Test-ExpiredContainerVersion (New-Version -Updated '2026-11-09T00:00:00Z') $Now | Should -BeFalse
    }
    It 'protects the exact 30-day boundary' {
        Test-ExpiredContainerVersion (New-Version -Created '2026-10-11T00:00:00Z') $Now | Should -BeFalse
    }
}

Describe 'Package inventory and REST contract' {
    It 'continues after a short page until an empty terminal page' {
        Mock Invoke-PackageApi {
            if ($Path -like '*page=1') { New-Version 1 }
            elseif ($Path -like '*page=2') { New-Version 2 }
            elseif ($Path -like '*page=3') { return @() }
            else { throw 'Unexpected page' }
        }
        $versions = Get-PackageVersions '/users/erikgraa/packages/container/powerospf'
        $versions.Count | Should -Be 2
        Should -Invoke Invoke-PackageApi -Times 3 -Exactly
    }
    It 'fails on duplicate pages instead of accepting an incomplete inventory' {
        Mock Invoke-PackageApi { New-Version }
        { Get-PackageVersions '/test' } | Should -Throw '*duplicate*'
    }
    It 'fails on a later page error' {
        Mock Invoke-PackageApi {
            if ($Path -like '*page=1') { New-Version } else { throw 'Forbidden' }
        }
        { Get-PackageVersions '/test' } | Should -Throw '*Forbidden*'
    }
    It 'fails on missing tags or invalid timestamps' {
        Mock Invoke-PackageApi { New-Version -Updated 'invalid' }
        { Get-PackageVersions '/test' } | Should -Throw
        Mock Invoke-PackageApi {
            $v = New-Version
            $v.metadata.container.tags = $null
            $v
        }
        { Get-PackageVersions '/test' } | Should -Throw '*tags*'
    }
    It 'rejects null and object responses rather than treating them as a terminal page' {
        $env:GH_TOKEN = 'fixture-only'
        try {
            Mock Invoke-WebRequest { @{ Content = 'null' } }
            { Invoke-PackageApi '/users/erikgraa/packages/container/powerospf/versions?per_page=100&page=1' } | Should -Throw
            Mock Invoke-WebRequest { @{ Content = '{}' } }
            { Invoke-PackageApi '/users/erikgraa/packages/container/powerospf/versions?per_page=100&page=1' } | Should -Throw
        } finally { Remove-Item Env:GH_TOKEN }
    }
    It 'accepts complete list pages, empty terminal pages, and single version objects' {
        $oldToken = $env:GH_TOKEN
        $env:GH_TOKEN = 'fixture-only'
        try {
            Mock Invoke-WebRequest { @{ Content = ConvertTo-Json -InputObject @((New-Version 1), (New-Version 2)) -Depth 10 } }
            @(Invoke-PackageApi '/users/erikgraa/packages/container/powerospf/versions?per_page=100&page=1').Count | Should -Be 2
            Mock Invoke-WebRequest { @{ Content = '[]' } }
            @(Invoke-PackageApi '/users/erikgraa/packages/container/powerospf/versions?per_page=100&page=2').Count | Should -Be 0
            Mock Invoke-WebRequest { @{ Content = ConvertTo-Json (New-Version) -Depth 10 } }
            (Invoke-PackageApi '/users/erikgraa/packages/container/powerospf/versions/1').id | Should -Be 1
        } finally { $env:GH_TOKEN = $oldToken }
    }
    It 'uses the documented API version and requires HTTP 204 for DELETE' {
        $env:GH_TOKEN = 'fixture-only'
        try {
            Mock Invoke-WebRequest { @{ StatusCode = 204 } } -ParameterFilter {
                $Method -eq 'DELETE' -and $Headers['X-GitHub-Api-Version'] -eq '2022-11-28'
            }
            Invoke-PackageApi '/users/erikgraa/packages/container/powerospf/versions/1' 'DELETE'
            Should -Invoke Invoke-WebRequest -Times 1
            Mock Invoke-WebRequest { @{ StatusCode = 200 } } -ParameterFilter {
                $Method -eq 'DELETE' -and $Headers['X-GitHub-Api-Version'] -eq '2022-11-28'
            }
            { Invoke-PackageApi '/test' 'DELETE' } | Should -Throw '*204*'
        } finally { Remove-Item Env:GH_TOKEN }
    }
}

Describe 'Manifest reference protection' {
    It 'protects nested indexes, shared children and subject manifests' {
        $root = New-Version 1 -Tags @('latest')
        $nested = New-Version 2
        $child = New-Version 3
        $subject = New-Version 4
        $script:Manifests = @{
            $root.name = [pscustomobject]@{
                schemaVersion = 2
                mediaType = 'application/vnd.docker.distribution.manifest.list.v2+json'
                manifests = @(@{ digest = $nested.name }, @{ digest = $child.name })
            }
            $nested.name = [pscustomobject]@{
                schemaVersion = 2
                mediaType = 'application/vnd.oci.image.index.v1+json'
                manifests = @(@{ digest = $child.name })
                subject = @{ digest = $subject.name }
            }
            $child.name = New-Manifest
            $subject.name = New-Manifest
        }
        $references = Get-ReferencedDigests @($root, $nested, $child) { param($digest) $Manifests[$digest] }
        foreach ($v in @($nested, $child, $subject)) { $references.Contains($v.name) | Should -BeTrue }
        $references.Contains($root.name) | Should -BeFalse
    }
    It 'fails on unreadable or unsupported manifests' {
        { Get-ReferencedDigests @((New-Version)) { throw 'Manifest unavailable' } } | Should -Throw '*unavailable*'
        { Get-ReferencedDigests @((New-Version)) { [pscustomobject]@{ schemaVersion = 1 } } } | Should -Throw '*schema*'
        { Get-ReferencedDigests @((New-Version)) {
            [pscustomobject]@{ schemaVersion = 2; mediaType = 'application/vnd.oci.image.index.v1+json'; manifests = @() }
        } } | Should -Throw '*Incomplete*'
    }
    It 'fails on registry digest mismatch' {
        Mock Invoke-WebRequest { @{ Headers = @{ 'Docker-Content-Digest' = 'wrong' }; Content = '{}' } }
        { Get-RegistryManifest erikgraa powerospf ('sha256:' + ('a' * 64)) fixture } | Should -Throw '*mismatch*'
    }
}

Describe 'Dry run and fail-closed execution' {
    BeforeEach {
        $script:Inventory = @((New-Version 1), (New-Version 2 -Tags @('latest')), (New-Version 3 -Tags @()))
        Mock Get-PackageVersions { return ,$Inventory }
        Mock Get-RegistryToken { 'fixture-token' }
        Mock Get-RegistryManifest { New-Manifest }
        Mock Invoke-PackageApi {
            if ($Method -ne 'DELETE') { return $Inventory | Where-Object { $Path.EndsWith("/$($_.id)") } }
        }
    }
    It 'is non-destructive by default' {
        Invoke-ContainerRetention erikgraa users powerospf -Now $Now
        Should -Invoke Invoke-PackageApi -Times 0
    }
    It 'deletes only eligible versions via the user-owned package endpoint' {
        Invoke-ContainerRetention erikgraa users powerospf -Now $Now -Apply
        Should -Invoke Invoke-PackageApi -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -eq '/users/erikgraa/packages/container/powerospf/versions/1'
        }
        Should -Invoke Get-PackageVersions -Times 2 -Exactly
    }
    It 'protects an old tagged child referenced by latest' {
        Mock Get-RegistryManifest {
            if ($Digest -eq $Inventory[1].name) {
                [pscustomobject]@{ schemaVersion = 2; mediaType = 'application/vnd.oci.image.index.v1+json'; manifests = @(@{ digest = $Inventory[0].name }) }
            } else { New-Manifest }
        }
        Invoke-ContainerRetention erikgraa users powerospf -Now $Now -Apply
        Should -Invoke Invoke-PackageApi -Times 0
    }
    It 'performs no deletion when manifest traversal fails' {
        Mock Get-RegistryManifest { throw 'Registry denied' }
        { Invoke-ContainerRetention erikgraa users powerospf -Now $Now -Apply } | Should -Throw '*denied*'
        Should -Invoke Invoke-PackageApi -Times 0
    }
    It 'performs no deletion when full inventory changes' {
        $script:Reads = 0
        Mock Get-PackageVersions {
            $script:Reads++
            if ($script:Reads -eq 1) { return ,$Inventory }
            return ,@($Inventory + (New-Version 4 -Tags @('nightly')))
        }
        { Invoke-ContainerRetention erikgraa users powerospf -Now $Now -Apply } | Should -Throw '*inventory changed*'
        Should -Invoke Invoke-PackageApi -Times 0
    }
    It 'stops if a candidate is retagged after inventory validation' {
        Mock Invoke-PackageApi { New-Version 1 -Tags @('latest') }
        { Invoke-ContainerRetention erikgraa users powerospf -Now $Now -Apply } | Should -Throw '*Candidate changed*'
        Should -Invoke Invoke-PackageApi -Times 0 -ParameterFilter { $Method -eq 'DELETE' }
    }
    It 'stops remaining deletions on an API error' {
        $script:Inventory = @((New-Version 1), (New-Version 2))
        Mock Invoke-PackageApi {
            if ($Method -eq 'DELETE') { throw 'Delete forbidden' }
            $Inventory | Where-Object { $Path.EndsWith("/$($_.id)") }
        }
        { Invoke-ContainerRetention erikgraa users powerospf -Now $Now -Apply } | Should -Throw '*forbidden*'
        Should -Invoke Invoke-PackageApi -Times 1 -Exactly -ParameterFilter { $Method -eq 'DELETE' }
    }
}
