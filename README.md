# MassRelay

MassRelay connects your own machines in a pocket network. Enrolled devices can see each other. A pair must approve access from both devices before either can connect. Each destination chooses whether to offer a shell. One binary provides the desktop client, user-mode listener, and public relay.

## Install

[MassRelay v0.2.0](https://github.com/zorkian/massrelay/releases/tag/v0.2.0) adds shared relays and the create-and-join flow.

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

Pushing a tag that matches the Cargo version, such as `v0.2.0`, builds and publishes the release binaries through GitHub Actions.

## Start a shared relay

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

Then run `massrelay run --allow-shell` on both machines and leave it running. In another terminal on each machine, approve the other.

```sh
# On laptop
massrelay approve workstation

# On workstation
massrelay approve laptop

# On either side, use the other device's name
massrelay shell laptop
```

Compare the endpoint ID shown by `approve` with the one that `massrelay run` prints on the other device. To script an approval, pass the verified endpoint ID instead of the name.

Use `massrelay peers` to see everyone in the pocket network, recent presence, and your pairing status. Any enrolled device can invite another with `massrelay invite` while `massrelay run` is running. Invites can be used once and expire after ten minutes. Use `massrelay decline NAME` to decline or unpair, or `massrelay revoke NAME` to remove another device from the network. Name matching is case-insensitive, and commands accept endpoint IDs as well.

Run `massrelay run` under your ordinary account in a terminal or supervisor of your choice. Use `--allow-shell` on each destination that should accept shells. Approving a peer on such a destination gives that peer the access of the account running MassRelay. Use `--shell /path/to/shell` to override the account's default shell executable, for example to use PowerShell on Windows.

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

Iroh authenticates peer keys and encrypts both directions of the shell. It can use direct connections or the configured relay. The relay manages the membership roster, coordinates pair approvals, and can see addressing and presence metadata. Each direct connection requires a locally saved approval for the authenticated peer key on **both** devices. A shell gives the peer access to your local account, including the ability to use that account's MassRelay connections to other devices.

If the relay goes offline, cached approvals still work over a reachable direct path. MassRelay saves peer address candidates, reuses its UDP port when possible, and uses local multicast discovery. Use a fixed `--bind` address and port if a device has a stable direct address you want it to keep. Behind NAT, establishing a new direct path can require the relay. Presence becomes unknown as the last heartbeat ages. Revocations take effect on each device when it next learns about them. A decline closes access locally as soon as you make it and syncs to the relay when it returns.

Keep the device state directory to preserve keys and approvals across restarts. If you lose every enrolled device, create a new pocket network. A plain shell ends on disconnection. Use the destination's terminal multiplexer if you need work to outlive a connection.

## Verification

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`. On Linux or macOS, run `cargo test --locked shell_works_with_only_a_tcp_relay_path -- --ignored` to test a shell with direct paths disabled. Build the debug binary and run `python3 tests/pocket.py target/debug/massrelay` for a three-device network on a ticket-only relay, followed by isolated networks and restarts on a shared relay. Both network tests use loopback ports.
