# MassRelay

MassRelay connects your own machines in a pocket network. Enrolled devices can see each other. A pair must approve access from both devices before either can connect. Each destination then chooses which services each peer may use, such as a shell or a TCP port. One binary provides the desktop client, user-mode listener, and public relay.

## Install

[MassRelay v0.4.0](https://github.com/zorkian/massrelay/releases/tag/v0.4.0) adds private discovery on Linux, macOS, and Windows.

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

## Private networks

Private discovery uses an encrypted membership history and a separate device profile. The release binaries include the `massrelay private` commands. See [Set up a private network](docs/private-discovery-setup.md) for relay setup, enrollment, and moving an existing network.

## Pair two machines

Run `massrelay` for a short overview and the next step, or `massrelay --help` for all commands. Use `massrelay status` when you need this device's full endpoint ID. To create a pocket network, ask the relay operator for its public locator, or [start your own relay](#start-a-shared-relay). On the first machine, set the locator and create the network.

```sh
export MASSRELAY_RELAY=mrrelay1_...
massrelay create
```

`massrelay create --relay mrrelay1_...` does the same without the environment variable. The only output on stdout is an invite for the second machine. If enrollment gets no reply, retry the original command with the same state directory and ticket or invite, if used. A retried `create` keeps the same network and prints the same invite while that invite is unused and unexpired, or a new one afterwards.

On the second machine, join with the invite. It already identifies the relay.

```sh
massrelay join mr1_...
```

To keep the invite out of shell history and process lists, run `massrelay join` and paste it at the prompt instead.

Use `massrelay create --copy` or `massrelay invite --copy` to copy the invite to your desktop clipboard. Then send it to the other device and paste it at the join prompt. On Linux, clipboard copy uses `wl-copy` on Wayland or `xclip` on X11. The default commands print the invite, so you can also use them over SSH or in a pipeline.

Each device is named after the first part of its machine's hostname, with unsupported characters replaced by hyphens. If no usable hostname is available, the name is derived from the device key. Add `--name NAME` to either command to choose a name, for example when two machines share a hostname. Names may contain ASCII letters, digits, hyphens, and underscores.

The complete forms are:

| Command | Creation ticket or invite | Device name |
| --- | --- | --- |
| `massrelay create [--relay LOCATOR] [--name NAME]` | None. Prints an invite. | `NAME` or hostname |
| `massrelay create NAME` | Operator creation ticket on stdin. Ignores `MASSRELAY_RELAY`. | `NAME` |
| `massrelay join INVITE [--name NAME]` | Argument | `NAME` or hostname |
| `massrelay join [--name NAME]` | Invite on stdin | `NAME` or hostname |
| `massrelay join NAME` | Invite on stdin | `NAME` |

`join` treats its argument as an invite only when it is a complete invite token, and otherwise as a device name.

Start MassRelay on both machines. On macOS and Linux with systemd, run [`massrelay install`](#run-in-the-background) to set up the background service. On other platforms, run `massrelay run` and leave it running. Then approve the other device from each machine.

```sh
# On laptop
massrelay approve workstation

# On workstation
massrelay approve laptop
```

When prompted to approve, run `massrelay status` on the other device and compare its full endpoint ID. To script an approval, pass the verified endpoint ID instead of the name.

Pairing alone gives no access. To open a shell from the laptop, allow it on the workstation.

```sh
# On workstation
massrelay enable shell laptop

# On laptop
massrelay shell workstation
```

Use `massrelay peers` to see devices in the network, recent presence, and pairing status. Use `massrelay peers --full` for full endpoint IDs in the terminal. Any enrolled device can run `massrelay invite` while its service is running. Invites can be used once and expire after ten minutes. Use `massrelay decline NAME` to decline or unpair, or `massrelay revoke NAME` to remove another device from the network. Name matching is case-insensitive, and commands accept full endpoint IDs as well.

Run `massrelay run` under your ordinary account in a terminal or supervisor of your choice. Use `--shell /path/to/shell` to override the account's default shell executable, for example to use PowerShell on Windows.

## Allow services

The device offering a service decides who may use it. You can grant access to individual peers or set a default for paired peers. Every service starts off. In these examples, the device `talaria` offers services to its paired peer `dirk`.

```sh
# On talaria
massrelay enable shell dirk
massrelay enable tcp:4000 dirk
massrelay list

# On dirk
massrelay connect talaria
massrelay connect talaria tcp:4000
```

Run `massrelay connect` in a terminal to choose a paired device and open a shell. You can also use `massrelay shell PEER`.

| Service | What the peer can do |
| --- | --- |
| `shell` | Open an interactive shell as the account running `massrelay run`, using `massrelay shell`. |
| `tcp:PORT` | Connect to that TCP port on the offering device's loopback address, IPv4 or IPv6. |
| `udp:PORT` | Exchange datagrams with that UDP port on `127.0.0.1` on the offering device. |

A shell gives the peer your account's access, including its ability to change MassRelay grants and to use its connections to other devices.

`massrelay enable` and `massrelay disable` need a running device service on the offering device and work while the relay is unreachable. Grants are saved there and survive restarts. Peers are given by name or endpoint ID, and an individual grant stays with that device's ID. You can enable a service before both approvals are in place. It takes effect once they are. Declining the pairing on either side or revoking the device removes its individual grants.

To stop a grant, disable it. Open sessions using it close, and other services and peers are unaffected.

```sh
massrelay disable tcp:4000 dirk
```

Omit the peer to set the default for this service.

```sh
massrelay enable shell
massrelay disable shell
```

`enable shell` lets current and future peers use your shell once you've both approved the pairing. `disable shell` turns off the default and closes sessions that depend on it. Individual grants and temporary exposures continue to apply.

Use `disable shell dirk` to exclude Dirk from an enabled default. That exception is saved across service restarts and default toggles. Use `enable shell dirk` to clear the exclusion and grant Dirk access individually. Defaults and exclusions appear in `massrelay list`. Grants saved by v0.3.10 are individual grants.

To expose a port with a different target to one peer, disable the default for that peer first. The exclusion will apply again when the temporary exposure ends.

`massrelay list` shows each grant's peer name, eight-character endpoint ID prefix, whether the grant is persistent or temporary, and where a port is forwarded. Use `massrelay list --full` for complete endpoint IDs. Grants are not announced to the relay or to other devices.

## Use a TCP port

`massrelay connect PEER tcp:PORT` carries one TCP connection over standard input and output. Output is the unmodified data from the port, and errors go to standard error.

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | massrelay connect talaria tcp:4000
```

Each direction closes separately. End of input is passed to the port, whose replies still arrive, and when the port finishes sending, standard output closes while input is still accepted. The command exits once both directions have closed, so in a terminal you may need Ctrl-D after the other end has finished.

## Expose a port temporarily

`massrelay expose` grants one peer a port only while the command runs. Run it on the device that offers the port.

```sh
# On talaria, leave this running
massrelay expose --tcp 4000 --to dirk

# On dirk
massrelay connect talaria tcp:4000
```

By default it forwards to loopback on the same port. Add `HOST:PORT` to forward elsewhere. The offering device resolves and connects to that address, so it can be any host that device can reach. The peer cannot choose or change it.

```sh
massrelay expose --tcp 4000 --to dirk 127.0.0.1:8080
massrelay expose --tcp 5432 --to dirk database.internal:5432
massrelay expose --tcp 8000 --to dirk '[::1]:8000'
```

The port after `--tcp` or `--udp` names the service that the peer asks for. Exposing a port requires a running `massrelay run`, and the exposure still needs both pairing approvals. Press Ctrl-C to end it. It also ends if the command is closed or killed, if `massrelay run` stops, if the pairing ends, or if you run `massrelay disable tcp:4000 dirk`. Its sessions close with it. Temporary grants are never saved. A peer can hold either a persistent or a temporary grant for a service; disable the existing one before replacing it.

## Use a UDP port

Expose a UDP port with `--udp`, or grant it persistently with `massrelay enable udp:PORT PEER`.

```sh
# On talaria, leave this running
massrelay expose --udp 5000 --to dirk

# On dirk, leave this running too
massrelay connect talaria udp:5000
```

`connect` listens on `127.0.0.1` on the same port and prints the address. Send datagrams there. Add `--listen PORT` to use another local port, for example when both devices are on one machine, or `--listen 0` to choose a free one. Stop it with Ctrl-C.

Each local sender address gets its own socket on the offering device, which keeps replies separate. These associations last until the session ends. A target given as a hostname is resolved when the session starts, preferring IPv4.

Datagram boundaries are preserved, including empty datagrams. The consumer's loopback socket is IPv4, so a payload is limited to 65,507 bytes. Between the devices, datagrams travel over one encrypted, reliable, ordered stream. A lost packet there delays the datagrams behind it instead of dropping them, which differs from native UDP and can add latency. Datagrams can still be lost at either local socket, for example when a sender outpaces the connection.

## Upgrade from v0.2.0 or earlier

Service grants replace the flag that `massrelay run` used to allow shells. The new version rejects that flag, so remove it from any LaunchAgent, service, or script before restarting. A LaunchAgent that still passes it exits at each start. Upgrade and restart `massrelay run` on both ends of every connection, because older and newer devices cannot open sessions with each other. Existing enrollment and pairings are kept. No shell or port is enabled after the upgrade until you grant it. Relays need no change.

## Run in the background

After creating or joining a network, stop any foreground `massrelay run` and run this from your ordinary account on macOS or Linux with systemd.

```sh
massrelay install
massrelay peers
```

On Linux, the command creates, starts, and enables the `massrelay-client.service` systemd user unit. Check it with `systemctl --user status massrelay-client.service` and follow the service log with `journalctl --user -u massrelay-client.service -f`. The JSONL event file is `connections.jsonl` in the device state directory. The service starts with your user manager. Running after logout or starting at boot requires systemd lingering for your account.

On macOS, the command writes and loads a LaunchAgent under your account. It starts immediately and at future logins. For the default profile, it uses `~/Library/LaunchAgents/com.massrelay.client.plist`, replacing the previous example plist if present. Follow the service log with `tail -f ~/Library/Logs/MassRelay.log`. The JSONL event file is `~/Library/Logs/MassRelay-connections.jsonl`.

With `--state-dir`, the command prints the service name and log locations for that profile. Use the same profile for these commands.

```sh
massrelay start
massrelay restart
massrelay stop
```

Use `start` to bring the background service up. If it's already running, its sessions continue. Use `restart` after updating the installed binary. Use `stop` to stop the service and close its current sessions. The installed service remains enabled for future logins. Each command records its outcome in the device event log.

Events appear in both the service log and the JSONL event file. They include device startup and shutdown, peers joining and leaving, approvals and pairing changes, services enabled or disabled, temporary exposures, and session connects, disconnects, and failures. Session events include the direction and session ID. Failures and disconnects include a reason and the shell exit code when available. Events include the peer's name and endpoint ID and the service when relevant. Shell commands, terminal output, forwarded data, forwarding addresses, and invitations stay out of the event log. In the foreground, events go to stderr and to `connections.jsonl` in the state directory. Use `massrelay run --log-file PATH` to set a different path.

Devices also audit enrollment, local commands and authentication failures, membership sync availability, state save errors, and failed peer handshakes. Enrollment events go to `connections.jsonl` in the state directory, including when the background service uses a different log file.

The relay writes `relay-events.jsonl` in its state directory and mirrors events to stderr. It audits network creation, enrollment, invite issuance, operator ticket reads, approvals, declines, revocations, control errors, and authenticated relay connection decisions and disconnects. The default systemd relay service mirrors stderr to `journalctl --user -u massrelay-relay.service`. Relay transport events include an ID for matching a connection with its disconnect. The device logs provide the peer and service information for end-to-end sessions. Routine successful roster heartbeats are omitted. Audit records use authenticated endpoint IDs when known and fixed reason codes so credentials, raw requests, and data payloads stay out of the logs.

## Start a shared relay

On a Linux host with systemd, pass `--relay` to the installer to install the binary and start a user service.

```sh
gh api repos/zorkian/massrelay/contents/install.sh -H 'Accept: application/vnd.github.raw+json' |
  sh -s -- --relay
```

The installer detects the public IP for a new relay and prints its public locator. To supply the address yourself, append `--public-ip ADDRESS` to the installer arguments. The service keeps its identity and membership under `${XDG_DATA_HOME:-$HOME/.local/share}/massrelay-relay`. Rerunning the relay installer updates the binary and restarts the service with the saved address. UDP `4433` and TCP `3340` must be reachable on that address.

`systemctl --user status massrelay-relay.service` shows the service status. To start it at boot and keep it running after logout, the service account needs systemd lingering enabled.

### Start the relay manually

One shared relay serves any number of independent pocket networks. On a reachable host, start it with the addresses that devices will use to reach it.

```sh
massrelay --state-dir ./relay-state relay \
  --public-udp 203.0.113.10:4433 --url http://relay.example.com:3340
```

Replace the example public IP and port and the relay URL. The first start creates the relay's key and saves these addresses and the shared mode in the state directory. Later, `massrelay --state-dir ./relay-state relay` is enough. Repeating the two flags with the saved values also works. A start with different values fails, as does adding the flags to a ticket-only relay. Keep the state directory private and preserve it across restarts.

The advertised addresses do not choose where the relay listens. By default it binds UDP `0.0.0.0:4433` for authenticated enrollment and membership traffic, and TCP `0.0.0.0:3340` for the Iroh relay. Use `--udp-bind` and `--relay-bind` for other addresses, on every start. Both ports must be reachable. `create` and `join` connect directly to the advertised UDP address, so a new device currently needs outbound UDP to it. After enrollment, control requests and shells can use the TCP relay if a direct path is unavailable. For an HTTPS relay URL, terminate TLS in front of the TCP listener with a reverse proxy that supports WebSocket upgrades.

A shared relay is open: anyone who can reach it can create a pocket network and relay their devices' traffic through it. It has no quotas or rate limits. Devices can see and pair with only the members of their own network. Use a [ticket-only relay](#run-a-ticket-only-relay) to control who creates networks.

The relay prints its public locator to stderr at each start. This command prints it to stdout, including while the relay runs.

```sh
massrelay --state-dir ./relay-state relay-info
```

MassRelay uses three kinds of strings.

| String | Starts with | Secret | Purpose |
| --- | --- | --- | --- |
| Relay locator | `mrrelay1_` | No | Names a shared relay by its key, UDP address, and URL. Used to create a network. |
| Operator creation ticket | `mr1_` | Yes, one use | Lets its holder create one network. |
| Join invite | `mr1_` | Yes, one use, ten minutes | Adds one device to one network. |

The locator determines which relay key your device trusts, so get it from the relay's operator over a channel you trust.

## Run a ticket-only relay

A ticket-only relay creates a network only for the holder of an operator creation ticket. Initialize its state directory, save the one-use ticket printed to stdout, and start it.

```sh
massrelay --state-dir ./private-relay-state relay-init \
  --public-udp 203.0.113.10:4433 --url http://relay.example.com:3340
massrelay --state-dir ./private-relay-state relay
```

The addresses, listener defaults, and reachability requirements are the same as for a shared relay. On the first device, run `massrelay create laptop` and paste the creation ticket on stdin. Invite other devices with `massrelay invite` while `massrelay run` is running, then join and approve them as above.

For another pocket network, print the next one-use creation ticket with `massrelay --state-dir ./private-relay-state relay-ticket`. Anyone holding an unused ticket can redeem it. Relay state created by earlier versions is ticket-only and stays that way. If an enrollment is still pending from v0.1.0, finish it with that client and the original ticket, or enroll from a new state directory.

## Connections and state

Iroh authenticates peer keys and encrypts both directions of every session. It can use direct connections or the configured relay. The relay manages the membership roster, coordinates pair approvals, and can see addressing and presence metadata. Each connection requires a locally saved approval for the authenticated peer key on **both** devices, and a grant for that peer and service on the offering device.

If the relay goes offline, cached approvals and grants still work over a reachable direct path. MassRelay saves peer address candidates, reuses its UDP port when possible, and uses local multicast discovery. Use a fixed `--bind` address and port if a device has a stable direct address you want it to keep. Behind NAT, establishing a new direct path can require the relay. Presence becomes unknown as the last heartbeat ages. Revocations take effect on each device when it next learns about them. A decline closes access locally as soon as you make it and syncs to the relay when it returns.

Keep the device state directory to preserve keys, approvals, and grants across restarts. If you lose every enrolled device, create a new pocket network. A plain shell ends on disconnection. Use the destination's terminal multiplexer if you need work to outlive a connection.

## Build from source

Install stable Rust and a platform C toolchain, then run `cargo build --locked --release --features private-membership` to build the same features as the release. The executable is `target/release/massrelay` or `target\release\massrelay.exe` on Windows.

Pushing a tag that matches the Cargo version, such as `v0.3.0`, builds and publishes the release binaries through GitHub Actions.

Pushes to `main` that change Cargo's manifests, configuration, toolchain, or the release workflow warm the Rust dependency cache for each platform. To warm the caches on demand, run the Release workflow manually on `main`.

## Verification

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`. On Linux or macOS, run `cargo test --locked shell_works_with_only_a_tcp_relay_path -- --ignored` to test a shell with direct paths disabled. Build the debug binary and run `python3 tests/pocket.py target/debug/massrelay` for a three-device network on a ticket-only relay, including service grants and TCP and UDP forwarding, followed by isolated networks and restarts on a shared relay. Both network tests use loopback ports.
