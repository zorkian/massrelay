$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('massrelay-installer-test-' + [Guid]::NewGuid())
$asset = 'massrelay-windows-x86_64.exe'
$installer = Join-Path (Split-Path $PSScriptRoot -Parent) 'install.ps1'
$script:assets = Join-Path $root 'assets'
$install = Join-Path $root 'install with spaces'
[IO.Directory]::CreateDirectory($script:assets) | Out-Null
$binary = Join-Path $script:assets $asset
$sums = Join-Path $script:assets 'SHA256SUMS'
$installed = Join-Path $install 'massrelay.exe'

# Substitute a local release download so all checks use disposable files.
function gh {
    $directory = $args[[Array]::IndexOf($args, '--dir') + 1]
    Copy-Item -LiteralPath $binary, $sums -Destination $directory
    $global:LASTEXITCODE = 0
}

try {
    Set-Content -LiteralPath $binary -Value 'first release' -Encoding ascii
    $first = (Get-FileHash -LiteralPath $binary).Hash
    Set-Content -LiteralPath $sums -Value "$first  $asset" -Encoding ascii
    & $installer -InstallDir $install
    if ((Get-FileHash -LiteralPath $installed).Hash -ne $first) {
        throw 'The installer did not copy the verified asset.'
    }

    Set-Content -LiteralPath $binary -Value 'second release' -Encoding ascii
    $rejected = $false
    try {
        & $installer -InstallDir $install
    } catch {
        if ($_.Exception.Message -ne 'The Windows binary checksum does not match the release.') {
            throw
        }
        $rejected = $true
    }
    if (-not $rejected -or (Get-FileHash -LiteralPath $installed).Hash -ne $first) {
        throw 'The mismatched asset replaced the installed file.'
    }

    $second = (Get-FileHash -LiteralPath $binary).Hash
    Set-Content -LiteralPath $sums -Value "$second  $asset" -Encoding ascii
    & $installer -InstallDir $install
    if ((Get-FileHash -LiteralPath $installed).Hash -ne $second) {
        throw 'The verified update did not replace the installed file.'
    }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
