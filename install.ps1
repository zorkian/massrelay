# Installs a released Windows x64 MassRelay executable for the current user.
[CmdletBinding()]
param(
    [string]$Version = $env:MASSRELAY_VERSION,
    [string]$InstallDir = $env:MASSRELAY_INSTALL_DIR
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'This installer requires Windows x64.'
}
if ($Version -and $Version -cnotmatch '^v[0-9][A-Za-z0-9.-]*$') {
    throw 'Set MASSRELAY_VERSION to a release tag such as v0.4.0.'
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI is required. Sign in with gh auth login before installing.'
}
if (-not $InstallDir) {
    $InstallDir = Join-Path $HOME 'bin'
}

$asset = 'massrelay-windows-x86_64.exe'
$stage = Join-Path ([IO.Path]::GetTempPath()) ('massrelay-' + [Guid]::NewGuid())
$pending = $null
[IO.Directory]::CreateDirectory($stage) | Out-Null
try {
    $download = @('release', 'download')
    if ($Version) {
        $download += $Version
    }
    $download += @('--repo', 'zorkian/massrelay', '--pattern', $asset, '--pattern', 'SHA256SUMS', '--dir', $stage)
    & gh @download
    if ($LASTEXITCODE -ne 0) {
        throw 'Release download failed. Check the tag and GitHub CLI access to zorkian/massrelay.'
    }
    $checksum = @(Get-Content -LiteralPath (Join-Path $stage 'SHA256SUMS') |
        Select-String -CaseSensitive -Pattern "^([a-fA-F0-9]{64}) [ *]$([regex]::Escape($asset))\s*$")
    if ($checksum.Count -ne 1) {
        throw 'The release must contain exactly one checksum for the Windows asset.'
    }

    $binary = Join-Path $stage $asset
    $expected = $checksum[0].Matches[0].Groups[1].Value
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash -ne $expected) {
        throw 'The Windows binary checksum does not match the release.'
    }

    $directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $destination = Join-Path $directory 'massrelay.exe'
    $pending = Join-Path $directory ('.massrelay-' + [Guid]::NewGuid() + '.exe')
    [IO.File]::Copy($binary, $pending)
    if ([IO.File]::Exists($destination)) {
        [IO.File]::Replace($pending, $destination, [NullString]::Value)
    } else {
        [IO.File]::Move($pending, $destination)
    }
    Write-Output "Installed $destination"
} finally {
    if ($pending -and [IO.File]::Exists($pending)) {
        [IO.File]::Delete($pending)
    }
    Remove-Item -LiteralPath $stage -Recurse -Force
}
