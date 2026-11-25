# MassRelay

MassRelay connects your own machines in a pocket network. Enrolled devices can see each other. A pair must approve access from both devices before either can connect. Each destination then chooses which services each peer may use, such as a shell or a TCP port. One binary provides the desktop client, user-mode listener, and public relay.

## Install

[MassRelay v0.3.0](https://github.com/zorkian/massrelay/releases/tag/v0.3.0) adds per-peer service grants, temporary TCP and UDP forwarding, and connection logs. If you already run MassRelay on your devices, see [the upgrade instructions](#upgrade-from-v020-or-earlier).

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

On Windows x64, sign in with GitHub CLI and run this in PowerShell.

```powershell
New-Item -ItemType Directory -Force "$HOME/bin" | Out-Null
gh release download --repo zorkian/massrelay --pattern massrelay-windows-x86_64.exe --output "$HOME/bin/massrelay.exe" --clobber
& "$HOME/bin/massrelay.exe" --version
```

Release binaries and their checksums are also available on the [Releases page](https://github.com/zorkian/massrelay/releases).

## Build from source

Install stable Rust and a platform C toolchain, then run `cargo build --locked --release`. The executable is `target/release/massrelay` or `target\release\massrelay.exe` on Windows.

Pushing a tag that matches the Cargo version, such as `v0.3.0`, builds and publishes the release binaries through GitHub Actions.

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

## Pair two machines

On the first machine, set the locator once for your shell and create a pocket network. No creation ticket or running `massrelay` process is needed.

```sh
export MASSRELAY_RELAY=mrrelay1_...
massrelay create
```

`massrelay create --relay mrrelay1_...` does the same without the environment variable. The only output on stdout is an invite for the second machine. If enrollment gets no reply, retry the original command with the same state directory and ticket or invite, if used. A retried `create` keeps the same network and prints the same invite while that invite is unused and unexpired, or a new one afterwards.

On the second machine, join with the invite. It already identifies the relay.

```sh
massrelay join mr1_...
```

Each device is named after the first part of its machine's hostname, with unsupported characters replaced by hyphens. If no usable hostname is available, the name is derived from the device key. Add `--name NAME` to either command to choose a name, for example when two machines share a hostname. Names may contain ASCII letters, digits, hyphens, and underscores. To keep an invite out of your shell history and process list, omit it and paste it on stdin.

The complete forms are:

| Command | Creation ticket or invite | Device name |
| --- | --- | --- |
| `massrelay create [--relay LOCATOR] [--name NAME]` | None. Prints an invite. | `NAME` or hostname |
| `massrelay create NAME` | Operator creation ticket on stdin. Ignores `MASSRELAY_RELAY`. | `NAME` |
| `massrelay join INVITE [--name NAME]` | Argument | `NAME` or hostname |
| `massrelay join [--name NAME]` | Invite on stdin | `NAME` or hostname |
| `massrelay join NAME` | Invite on stdin | `NAME` |

`join` treats its argument as an invite only when it is a complete invite token, and otherwise as a device name.

Then run `massrelay run` on both machines and leave it running. In another terminal on each machine, approve the other.

```sh
# On laptop
massrelay approve workstation

# On workstation
massrelay approve laptop
```

Compare the endpoint ID shown by `approve` with the one that `massrelay run` prints on the other device. To script an approval, pass the verified endpoint ID instead of the name.

Pairing alone gives no access. To open a shell from the laptop, allow it on the workstation.

```sh
# On workstation
massrelay enable shell laptop

# On laptop
massrelay shell workstation
```

Use `massrelay peers` to see everyone in the pocket network, recent presence, and your pairing status. Any enrolled device can invite another with `massrelay invite` while `massrelay run` is running. Invites can be used once and expire after ten minutes. Use `massrelay decline NAME` to decline or unpair, or `massrelay revoke NAME` to remove another device from the network. Name matching is case-insensitive, and commands accept endpoint IDs as well.

Run `massrelay run` under your ordinary account in a terminal or supervisor of your choice. Use `--shell /path/to/shell` to override the account's default shell executable, for example to use PowerShell on Windows.

## Allow services

The device offering a service decides who may use it. Each grant names one peer and one service, and every device starts with none. In these examples, the device `talaria` offers services to its paired peer `dirk`.

```sh
# On talaria
massrelay enable shell dirk
massrelay enable tcp:4000 dirk
massrelay list

# On dirk
massrelay shell talaria
massrelay connect talaria tcp:4000
```

| Service | What the peer can do |
| --- | --- |
| `shell` | Open an interactive shell as the account running `massrelay run`, using `massrelay shell`. |
| `tcp:PORT` | Connect to that TCP port on the offering device's loopback address, IPv4 or IPv6. |
| `udp:PORT` | Exchange datagrams with that UDP port on `127.0.0.1` on the offering device. |

A shell gives the peer your account's access, including its ability to change MassRelay grants and to use its connections to other devices.

`massrelay enable` and `massrelay disable` need `massrelay run` on the offering device, and work while the relay is unreachable. Grants are saved there and survive restarts. Peers are given by name or endpoint ID, and a grant stays with that device's ID. You can enable a service before both approvals are in place; it takes effect once they are. Declining the pairing on either side, or revoking the device, removes its grants, so enable them again after a new approval.

To stop a grant, disable it. Open sessions using it close, and other services and peers are unaffected.

```sh
massrelay disable tcp:4000 dirk
```

`massrelay list` shows this device's grants with each peer's name and endpoint ID, whether the grant is persistent or temporary, and where a port is forwarded. Grants are not announced to the relay or to other devices.

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

## Run in the background on macOS

After creating or joining a network, stop any foreground `massrelay run` and load a LaunchAgent under your account. This example writes connection events to `~/Library/Logs/MassRelay-connections.jsonl`. Use `massrelay enable` to allow peers to use services.

```sh
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
plist="$HOME/Library/LaunchAgents/com.massrelay.client.plist"
cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.massrelay.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>$HOME/.local/bin/massrelay</string>
    <string>run</string>
    <string>--log-file</string>
    <string>$HOME/Library/Logs/MassRelay-connections.jsonl</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>$HOME/Library/Logs/MassRelay.log</string>
</dict>
</plist>
EOF
plutil -lint "$plist" && launchctl bootstrap "gui/$(id -u)" "$plist"
```

If the agent is already loaded, run `launchctl bootout "gui/$(id -u)/com.massrelay.client"` before reloading the plist. Use `massrelay peers` to check the agent and `tail -f ~/Library/Logs/MassRelay-connections.jsonl` to watch connections.

Connection events are one JSON object per line. Each records the UTC time, direction, session number, the peer's name and endpoint ID when known, and the service when known. Failed and disconnect events include the reason, and on the shell host the exit code if available. Shell commands, terminal output, forwarded data, forwarding addresses, and invitations stay out of the connection log. Use `massrelay run --log-file PATH` for the same log from a terminal. By default, connection events go to stderr.

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

## Verification

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`. On Linux or macOS, run `cargo test --locked shell_works_with_only_a_tcp_relay_path -- --ignored` to test a shell with direct paths disabled. Build the debug binary and run `python3 tests/pocket.py target/debug/massrelay` for a three-device network on a ticket-only relay, including service grants and TCP and UDP forwarding, followed by isolated networks and restarts on a shared relay. Both network tests use loopback ports.
