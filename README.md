# MassRelay

MassRelay connects your own machines in a pocket network. Enrolled devices can see each other. A pair must approve access from both devices before either can connect. Each destination then chooses which services each peer may use, such as a shell or a TCP port. One binary provides the client, user-mode listener, and relay.

## Install

MassRelay runs on Linux, macOS, and Windows x64.

On Linux or macOS, sign in with `gh auth login` using an account that has access to this repository. Then install the latest release to `~/.local/bin/massrelay`.

```sh
gh api repos/zorkian/massrelay/contents/install.sh -H 'Accept: application/vnd.github.raw+json' | sh
```

You can also fetch the installer with curl using your GitHub CLI session.

```sh
gh auth token |
  awk '{ printf "header = \"Authorization: Bearer %s\"\n", $0 }' |
  curl -fsSL --config - -H 'Accept: application/vnd.github.raw+json' \
    https://api.github.com/repos/zorkian/massrelay/contents/install.sh | sh
```

If the repository becomes public, curl can fetch it directly.

```sh
curl -fsSL https://raw.githubusercontent.com/zorkian/massrelay/main/install.sh | sh
```

The installer selects the x86-64 or ARM64 binary and verifies its SHA-256 checksum. Set `MASSRELAY_VERSION` in the environment to install a specific tag. If `~/.local/bin` is outside your `PATH`, run `~/.local/bin/massrelay --version` or add `export PATH="$HOME/.local/bin:$PATH"` to your shell startup file.

On Windows x64 (Windows 10 version 1809 or later), sign in with GitHub CLI and run this in PowerShell. The installer verifies the release checksum before replacing `massrelay.exe`.

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

Release binaries and their checksums are also available on the [Releases page](https://github.com/zorkian/massrelay/releases).

## Set up a network

Ask your relay operator for a locator, or [run your own relay](docs/private-discovery-setup.md). On the first device run `massrelay create`, paste the locator, and start `massrelay run`. Send the invite printed by `create` to the second device over a trusted channel. On the second device run `massrelay join`, paste the invite, and start `massrelay run`.

`massrelay create --relay LOCATOR` and `MASSRELAY_RELAY` are also supported. Use `massrelay create --copy` or `massrelay invite --copy` to copy an invite to the clipboard. On Linux this uses `wl-copy` or `xclip`. Invites work once and expire in ten minutes. An enrolled device can issue a new one using `massrelay invite` while its runtime is running.

## Pair and connect

Run `massrelay status` on each device to verify its full endpoint ID. Device names default to the hostname. Set one with `create --name NAME` or `join --name NAME`. Approve the other device on both ends. On the device offering shell access, enable it for the approved peer.

```sh
# On the workstation
massrelay approve LAPTOP_ENDPOINT_ID --as laptop
massrelay enable shell laptop

# On the laptop
massrelay approve WORKSTATION_ENDPOINT_ID --as workstation
massrelay shell workstation
```

Pairing completes on the next connection attempt. You can set a grant before pairing. It takes effect after both devices approve each other. Use `massrelay peers` to see membership and pairing decisions. Run `massrelay connect` in a terminal to pick an approved device, or give it a peer and service directly.

Run `massrelay decline PEER` to end a pairing. Run `massrelay revoke PEER` to cut off the peer locally and remove it from the network when membership sync completes.

## Share services

A destination chooses which peers can access each service. Shell access gives the peer the privileges of the account running MassRelay. The destination can choose the executable with `massrelay run --shell PATH`. For Windows PowerShell, use `massrelay run --shell powershell.exe`.

```sh
# On the workstation
massrelay enable tcp:4000 laptop
massrelay enable udp:5000 laptop
massrelay list

# On the laptop
massrelay connect workstation tcp:4000
massrelay connect workstation udp:5000 --listen 0
```

TCP uses standard input and output and supports independent half-closes. UDP listens on a loopback port and prints its address. Datagrams retain their boundaries over an encrypted, reliable stream. Persistent grants forward to the destination's loopback address. A temporary `expose` grant can forward elsewhere from that device.

```sh
massrelay expose --tcp 4000 --to laptop 127.0.0.1:8080
massrelay expose --udp 5000 --to laptop
```

An exposure lasts while its command runs. Declining, revoking, or disabling the peer's grant ends the affected sessions. Omit the peer in `massrelay enable SERVICE` to set a default for paired peers, or in `massrelay disable SERVICE` to turn the default off. Disable a named peer to exclude it from the default.

## Run in the background

On macOS and Linux with systemd, run `massrelay install` after enrollment to set up the user service. Use `massrelay start`, `restart`, or `stop` with the same state directory. On Windows, run `massrelay run` in a terminal or under your supervisor.

Linux uses the `massrelay-client.service` systemd user unit for the default profile. macOS uses `com.massrelay.client` and writes its service log to `~/Library/Logs/MassRelay.log`. The installer prints the paths. The connection audit file is `connections.jsonl` by default. It contains one JSON object per line. `massrelay run --log-file PATH` selects a different audit file. Console and supervisor messages use plain text.

## Inspect a running device

Run `massrelay status` in another terminal to see active inbound and outbound shells and port forwards. Each row shows the peer, service, and current route. Run `massrelay list` to see the shell and port permissions on this device, including defaults, exclusions, and temporary exposures with their targets. `massrelay peers` shows membership, approvals, and pairing state.

## How connections work

The forwarding relay can see the endpoint IDs it forwards between, their relay-facing IP addresses, and the size and timing of encrypted packets. Shell and port traffic remains end-to-end encrypted on either route. The forwarding relay cannot read the service type, destination service port, or payload.

The membership mailbox is a service operated by the relay. It can distinguish membership and invite operations, and sees access credentials, opaque storage handles, and ciphertext sizes and timing. Devices encrypt and verify the membership and invite contents. The mailbox has no plaintext roster or device names.

A cached, reachable direct path can keep working through a relay outage, including after restart when the same UDP port can be reused. Keep the profile directory to retain the device's keys, approvals, and grants.

## Build and verify

Install stable Rust and a platform C toolchain. Run `cargo build --locked --release` for the same build as the release. Run `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and on Unix run `cargo test --locked -- --ignored --test-threads=1` for native network and shell tests. On Linux, `python3 tests/private.py target/release/massrelay` runs the complete CLI workflow on loopback.
