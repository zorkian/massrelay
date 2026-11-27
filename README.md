# MassRelay

Open a shell on your home workstation from your laptop, or reach a development service on another machine without opening a port on your router. MassRelay connects your devices in a small network and lets each device decide who can use its shell and TCP or UDP services.

Connections go directly between devices when possible and fall back to a relay when needed. Either way, shell and port traffic is end-to-end encrypted. The same binary runs on your devices and can host a relay on Linux or macOS.

## Install MassRelay

Release binaries are available for Linux and macOS on x86-64 and ARM64, and for Windows x86-64 on Windows 10 version 1809 or later.

Sign in with `gh auth login` before running the installer, or download the binary from [GitHub Releases](https://github.com/zorkian/massrelay/releases).

The installers use the latest release by default. Set `MASSRELAY_VERSION` to a tag to install a specific version.

### Linux and macOS

```sh
gh api repos/zorkian/massrelay/contents/install.sh -H 'Accept: application/vnd.github.raw+json' | sh
massrelay --version
```

The binary goes in `~/.local/bin`. If your shell can't find it, add that directory to your `PATH` or call `~/.local/bin/massrelay` directly.

### Windows

Run in PowerShell.

```powershell
$installer = Join-Path $env:TEMP ("massrelay-install-" + [Guid]::NewGuid() + ".ps1")
try {
    gh api repos/zorkian/massrelay/contents/install.ps1 -H 'Accept: application/vnd.github.raw+json' > $installer
    if ($LASTEXITCODE -ne 0) { throw 'Could not download the MassRelay installer.' }
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
    if ($LASTEXITCODE -ne 0) { throw 'MassRelay installation failed.' }
} finally {
    Remove-Item -LiteralPath $installer -ErrorAction SilentlyContinue
}
& "$HOME/bin/massrelay.exe" --version
```

## Open your first remote shell

Get a **relay locator** from your relay operator, or [set up your own relay](docs/private-discovery-setup.md). Then connect two devices.

1. On your **workstation**, run `massrelay create` and paste the locator. Save the invite it prints, then run `massrelay run`. Keep it running while the laptop joins.
2. Send the invite to your **laptop** through a trusted channel. Run `massrelay join`, paste the invite, then run `massrelay run`. An invite works once and expires in ten minutes. From an enrolled device that's running, use `massrelay invite` to make another.
3. In a separate terminal on each machine, run `massrelay status` and verify its endpoint ID. Each device approves the other's ID. The workstation also grants the laptop shell access.

On the workstation:

```sh
massrelay approve LAPTOP_ENDPOINT_ID --as laptop
massrelay enable shell laptop
```

On the laptop:

```sh
massrelay approve WORKSTATION_ENDPOINT_ID --as workstation
massrelay shell workstation
```

The devices finish pairing on the first connection attempt. You can also run `massrelay connect` without arguments in a terminal to pick an approved device.

Device names default to your hostname. Use `--name NAME` when creating or joining, or `--copy` on `create` and `invite` to put the invite on your clipboard.

## Share a service

Enable a service on the device that hosts it, then connect from the approved peer. For example, to give the laptop access to TCP port 4000 on the workstation:

```sh
# Workstation
massrelay enable tcp:4000 laptop

# Laptop
massrelay connect workstation tcp:4000
```

TCP connects through standard input and output. For UDP, grant an exact service such as `udp:5000` and connect with `massrelay connect workstation udp:5000 --listen 0`. MassRelay prints the local address where your application can send datagrams.

Persistent port grants reach services on the host's loopback address. Use `expose` to share one temporarily, with an optional target address:

```sh
massrelay expose --tcp 4000 --to laptop 127.0.0.1:8080
```

The exposure ends when the command exits. Omit the peer when enabling or disabling a service to change the default for paired devices. Disable a service for a named peer to exclude that peer from the default.

On Linux and macOS, shells run with the MassRelay account's usual permissions. On Windows, shells are regular by default. If the destination runs as an administrator, `massrelay shell PEER --elevated` can use the same shell grant to open an administrator shell. The destination chooses the shell executable with `massrelay run --shell PATH`.

## Keep MassRelay running

After creating or joining a network, stop any foreground `massrelay run` and run `massrelay install` to start a background service. Use `massrelay start`, `massrelay stop`, and `massrelay restart` to manage it. Linux uses a systemd user unit. macOS uses a LaunchAgent in your login session.

On Windows, open an elevated PowerShell under the same account that enrolled the device. Run `massrelay install --allow-administrator` and enter the account password at the prompt. The service starts before sign-in and uses Windows PowerShell by default. Use an elevated local terminal for service controls, and rerun `install` if the password changes. Stop the service before rerunning `install.ps1` to upgrade the binary.

## See what's happening

| Command | What it shows |
| --- | --- |
| `massrelay status` | Active shells and forwards in both directions, whether each is direct or relayed, and the last reported peer versions |
| `massrelay peers` | Network members, names, approvals, and pairing state |
| `massrelay list` | Shell and port grants, defaults, exclusions, and active exposures |
| `massrelay ping PEER` | Round-trip time and packet loss to a mutually approved peer. Use `-c` to change the probe count. |
| `massrelay logs` | Recent runtime diagnostics, approvals, grants, and connections. Add `--follow` for live output. |

Diagnostics come from the operating system. Entries marked `[audit]` come from MassRelay's local connection log. If you ran the daemon with a custom `--log-file PATH`, pass that path to `massrelay logs --log-file PATH`.

Use `massrelay rename NEW_NAME` to change how this device introduces itself to peers. They learn the new name the next time you connect after mutual approval. Use `massrelay rename PEER NEW_NAME` to change a local alias using the peer's current alias or exact endpoint ID. Both forms preserve permissions and live connections.

Use `massrelay decline PEER` to end a pairing. Use `massrelay revoke PEER` to cut off access immediately on this device and remove the peer from the network once membership syncs.

## What the relay can see

A forwarding relay sees which endpoint IDs it forwards between, their relay-facing IP addresses, and packet sizes and timing. It cannot read shell or port traffic, identify the requested service or port, or see the contents of a session. A reachable direct route can keep working while the relay is down.

The relay also hosts an encrypted mailbox for membership and invites. It can see operation types, access credentials, opaque storage handles, and ciphertext sizes and timing. Devices encrypt and verify the contents, including the roster and device names.

## Upgrading and building

Use the installer again to upgrade, then restart the daemon. Update both ends to use ping or explicit shell privilege requests. If you're upgrading from relay-managed membership in v0.4.0 or earlier, [create a new encrypted network](docs/private-discovery-setup.md).

To build from source, install stable Rust and a platform C toolchain, then run `cargo build --locked --release`. Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings` to check the code. On Unix, `cargo test --locked -- --ignored --test-threads=1` covers native networking and shells. On Linux, `python3 tests/private.py target/release/massrelay` exercises the CLI on loopback.

## License

MassRelay is available under the [MIT License](LICENSE).
