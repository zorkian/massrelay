#Requires -Version 7
<#
Exercises 'massrelay install', 'start', 'stop' and 'restart' against the real Windows Service
Control Manager, using a profile whose relay is an unused loopback port.

The service logs on as the account running this script, so Windows needs that account's
password:

  -ResetAccountPassword   Sets the account's password to a random one. Only allowed on a
                          GitHub Actions runner, which is thrown away afterwards.
  -Password               The account's existing password, on a machine you keep:
                          ./tests/service-windows.ps1 -Password (Read-Host -AsSecureString)

Run it from an elevated PowerShell in the repository, after 'cargo build --release'. It
registers a service for a throwaway state directory under the user profile and removes it.
With -Password the account keeps the "Log on as a service" right the install granted.

-ConPty also launches PowerShell through ConPTY under a service logon (session 0,
no interactive console) by registering a test executable as a throwaway service.
#>
[CmdletBinding()]
param(
    [string]$Binary,
    [securestring]$Password,
    [switch]$ResetAccountPassword,
    [switch]$ConPty
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows) {
    throw 'This fixture needs Windows.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$administrator = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not [Security.Principal.WindowsPrincipal]::new($identity).IsInRole($administrator)) {
    throw 'Run this fixture from an elevated PowerShell.'
}
$repository = Split-Path $PSScriptRoot -Parent
if (-not $Binary) {
    $Binary = Join-Path $repository 'target\release\massrelay.exe'
}
$user = $identity.Name.Split('\')[-1]

if ($Password) {
    $secret = [Net.NetworkCredential]::new('', $Password).Password
} elseif ($ResetAccountPassword) {
    if ($env:GITHUB_ACTIONS -ne 'true') {
        throw '-ResetAccountPassword changes this account''s password and is only allowed on a CI runner. Pass -Password instead.'
    }
    $random = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Fill($random)
    # The prefix satisfies a password complexity policy.
    $secret = 'Mr1!' + [Convert]::ToHexString($random)
    ([ADSI]"WinNT://$env:COMPUTERNAME/$user,user").SetPassword($secret)
} else {
    throw 'Pass -Password, or -ResetAccountPassword on a disposable CI runner.'
}

# Run a program with exact arguments and standard input, without PowerShell's own handling
# of native output.
function Invoke-Tool {
    param([string]$Path, [string[]]$Arguments, [string]$Stdin)
    $start = [Diagnostics.ProcessStartInfo]::new($Path)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.ReadToEndAsync()
    $errors = $process.StandardError.ReadToEndAsync()
    if ($Stdin) {
        $process.StandardInput.WriteLine($Stdin)
    }
    $process.StandardInput.Close()
    $process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Output   = $output.GetAwaiter().GetResult()
        Error    = $errors.GetAwaiter().GetResult()
    }
}

function Assert {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

$id = [Guid]::NewGuid().ToString('N')
# Under the user profile, which only this account and administrators can write. The
# temporary directory is avoided: its path is often a short (8.3) name.
$root = Join-Path $env:USERPROFILE "massrelay-service-test-$id"
$state = Join-Path $root 'state with spaces'
$exe = Join-Path $root 'bin\massrelay.exe'
$marker = Join-Path $state 'private-experimental-0\private-runtime.json'
$install = @('--state-dir', $state, 'install', '--password-stdin')

# Every service this run registered has the throwaway directory in its command line.
function Get-TestService {
    Get-CimInstance Win32_Service -Filter "PathName LIKE '%$id%'"
}

function Get-DeviceService {
    param([string]$Name)
    Get-CimInstance Win32_Service -Filter "Name='$Name'"
}

function Invoke-Device {
    param([string[]]$Arguments)
    Invoke-Tool $exe (@('--state-dir', $state) + $Arguments) ''
}

function Test-Runtime {
    (Invoke-Device @('status')).Output -match 'Runtime: running'
}

Push-Location $repository
try {
    New-Item -ItemType Directory -Path (Split-Path $exe -Parent) | Out-Null
    Copy-Item -LiteralPath $Binary -Destination $exe

    $env:MASSRELAY_FIXTURE_STATE_DIR = $state
    try {
        & cargo +stable test --locked --release write_an_offline_fixture_profile -- --ignored
        Assert ($LASTEXITCODE -eq 0) 'The fixture profile test failed.'
    } finally {
        Remove-Item Env:MASSRELAY_FIXTURE_STATE_DIR
    }
    Assert (Test-Path -LiteralPath (Join-Path $state 'private-experimental-0\private-device.json')) 'No fixture profile was written.'

    # An administrator account must opt in to a service with administrator rights.
    $refused = Invoke-Tool $exe $install $secret
    Assert ($refused.ExitCode -ne 0 -and $refused.Error -match '--allow-administrator') "An administrator's service was not refused: $($refused.Error)"
    $install += '--allow-administrator'

    # An account with read access to enrollment secrets could impersonate the service.
    $profile = Join-Path $state 'private-experimental-0\private-device.json'
    & icacls.exe $profile /grant '*S-1-5-32-545:(R)' | Out-Null
    Assert ($LASTEXITCODE -eq 0) 'Could not make the deliberately readable profile.'
    $refused = Invoke-Tool $exe $install $secret
    Assert ($refused.ExitCode -ne 0 -and $refused.Error -match 'unsafe access') "A readable profile was not refused: $($refused.Error)"
    & icacls.exe $profile /remove:g '*S-1-5-32-545' | Out-Null
    Assert ($LASTEXITCODE -eq 0) 'Could not restore the private profile permissions.'

    # A program that other accounts can replace must not become a service.
    $loose = Join-Path $root 'loose'
    New-Item -ItemType Directory -Path $loose | Out-Null
    Copy-Item -LiteralPath $exe -Destination $loose
    & icacls.exe $loose /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    Assert ($LASTEXITCODE -eq 0) 'Could not loosen the test directory.'
    $refused = Invoke-Tool (Join-Path $loose 'massrelay.exe') $install $secret
    Assert ($refused.ExitCode -ne 0 -and $refused.Error -match 'S-1-5-32-545') "A program writable by Users was not refused: $($refused.Error)"

    # A wrong password is found before anything is registered.
    $refused = Invoke-Tool $exe $install 'not-the-password'
    Assert ($refused.ExitCode -ne 0) 'A wrong password was accepted.'
    Assert (@(Get-TestService).Count -eq 0) 'A refused install left a service behind.'

    $installed = Invoke-Tool $exe $install $secret
    Assert ($installed.ExitCode -eq 0) "install failed: $($installed.Error)"
    Assert ($installed.Output -match 'MassRelay-[0-9a-f]{16}') "install did not name its service: $($installed.Output)"
    $name = $Matches[0]
    $service = Get-DeviceService $name
    Assert ($null -ne $service) "The service $name is not registered."
    Assert ($service.StartMode -eq 'Auto') "The service does not start with Windows: $($service.StartMode)"
    Assert ($service.StartName -match ('\\' + [regex]::Escape($user) + '$')) "The service runs as $($service.StartName), not $user."
    Assert ($service.PathName.StartsWith("`"$exe`" ", [StringComparison]::OrdinalIgnoreCase)) "Unexpected command line: $($service.PathName)"
    Assert ($service.State -eq 'Running') "The service is $($service.State) after install."
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
    Assert ($process.SessionId -eq 0) "The service runs in session $($process.SessionId), not the services session."
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
    Assert ($owner.User -eq $user) "The service process belongs to $($owner.User)."
    Assert (Test-Runtime) 'The runtime does not answer local commands under the service.'
    Assert (Get-Acl -LiteralPath $marker).AreAccessRulesProtected 'The control key inherits the directory ACL.'
    $audit = Join-Path $state 'connections.jsonl'
    Assert (Get-Acl -LiteralPath $audit).AreAccessRulesProtected 'The audit log inherits the directory ACL.'
    $logged = Invoke-Device @('logs')
    Assert ($logged.ExitCode -eq 0 -and $logged.Output -match 'the runtime started') "Service diagnostics did not reach the Windows Event Log: $($logged.Output) $($logged.Error)"
    $first = $service.ProcessId

    # A second install replaces the registration and restarts the one service.
    $again = Invoke-Tool $exe $install $secret
    Assert ($again.ExitCode -eq 0) "The second install failed: $($again.Error)"
    Assert (@(Get-TestService).Count -eq 1) 'The second install registered another service.'
    $service = Get-DeviceService $name
    Assert ($service.State -eq 'Running' -and $service.ProcessId -ne $first) 'The second install did not restart the service.'

    foreach ($attempt in 1..2) {
        $stopped = Invoke-Device @('stop')
        Assert ($stopped.ExitCode -eq 0) "stop failed: $($stopped.Error)"
    }
    $service = Get-DeviceService $name
    Assert ($service.State -eq 'Stopped') "The service is $($service.State) after stop."
    Assert ($service.ExitCode -eq 0) "The service reported exit code $($service.ExitCode) for a requested stop."
    # The runtime removes its marker only in its ordered stop.
    Assert (-not (Test-Path -LiteralPath $marker)) 'The runtime did not stop in order.'

    & icacls.exe $audit /grant '*S-1-5-32-545:(R)' | Out-Null
    Assert ($LASTEXITCODE -eq 0) 'Could not make the deliberately readable audit log.'
    $refused = Invoke-Device @('start')
    Assert ($refused.ExitCode -ne 0) 'A readable audit log was accepted.'
    & icacls.exe $audit /remove:g '*S-1-5-32-545' | Out-Null
    Assert ($LASTEXITCODE -eq 0) 'Could not restore the private audit log permissions.'

    $auditTarget = Join-Path $state 'audit-target.jsonl'
    Move-Item -LiteralPath $audit -Destination $auditTarget
    $auditHash = (Get-FileHash -LiteralPath $auditTarget).Hash
    try {
        New-Item -ItemType SymbolicLink -Path $audit -Target $auditTarget | Out-Null
        $refused = Invoke-Device @('start')
        Assert ($refused.ExitCode -ne 0) 'A symlink at the audit path was accepted.'
        Assert ((Get-FileHash -LiteralPath $auditTarget).Hash -eq $auditHash) 'The service wrote through an audit symlink.'
    } finally {
        [IO.File]::Delete($audit)
        Move-Item -LiteralPath $auditTarget -Destination $audit
    }

    foreach ($attempt in 1..2) {
        $started = Invoke-Device @('start')
        Assert ($started.ExitCode -eq 0) "start failed: $($started.Error)"
    }
    $service = Get-DeviceService $name
    Assert ($service.State -eq 'Running') "The service is $($service.State) after start."
    Assert (Test-Runtime) 'The runtime does not answer after start.'
    $first = $service.ProcessId

    $restarted = Invoke-Device @('restart')
    Assert ($restarted.ExitCode -eq 0) "restart failed: $($restarted.Error)"
    $service = Get-DeviceService $name
    Assert ($service.State -eq 'Running' -and $service.ProcessId -ne $first) 'restart did not start a new process.'
    Assert (Test-Runtime) 'The runtime does not answer after restart.'

    $stopped = Invoke-Device @('stop')
    Assert ($stopped.ExitCode -eq 0) "stop after restart failed: $($stopped.Error)"
    Start-Sleep -Seconds 6
    Assert ((Get-DeviceService $name).State -eq 'Stopped') 'The service unexpectedly started again after stop.'

    if ($ConPty) {
        $tests = & cargo +stable test --locked --release --no-run --message-format=json |
            ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.executable } |
            Select-Object -Last 1 -ExpandProperty executable
        Assert ([bool]$tests) 'Could not find the unit-test executable.'
        $probe = "MassRelayConPtyProbe-$($id.Substring(0, 8))"
        $probeExe = Join-Path $root 'probe.exe'
        $done = Join-Path $root 'probe.result'
        Copy-Item -LiteralPath $tests -Destination $probeExe
        @{ name = $probe; state = $state; result = $done } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $root 'probe.json') -Encoding utf8NoBOM
        $credential = [pscredential]::new("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $secret -AsPlainText -Force))
        New-Service -Name $probe -BinaryPathName "`"$probeExe`" scm_powershell_probe --ignored --test-threads=1" -Credential $credential -StartupType Manual | Out-Null
        Start-Service -Name $probe
        $scmProbe = Get-DeviceService $probe
        $probeProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($scmProbe.ProcessId)"
        Assert ($probeProcess.SessionId -eq 0) 'The PowerShell probe did not run in the services session.'
        $deadline = (Get-Date).AddSeconds(60)
        while (-not (Test-Path -LiteralPath $done) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        Assert (Test-Path -LiteralPath $done) 'PowerShell did not finish under a service logon.'
        $output = Get-Content -LiteralPath $done -Raw
        Assert ($output -eq 'ok') "PowerShell failed under a service logon: $output"
        Stop-Service -Name $probe
    }
    Write-Output "The Windows service fixture passed for $name."
} catch {
    if (Test-Path -LiteralPath $exe) {
        $logged = Invoke-Device @('logs')
        Write-Host $logged.Output
        Write-Host $logged.Error
    }
    throw
} finally {
    Pop-Location
    foreach ($service in Get-TestService) {
        & sc.exe stop $service.Name | Out-Null
        $deadline = (Get-Date).AddSeconds(90)
        while ((Get-DeviceService $service.Name).State -ne 'Stopped' -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        & sc.exe delete $service.Name | Out-Null
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
