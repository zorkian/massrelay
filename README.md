# MassRelay

MassRelay connects your own machines in a pocket network. Enrolled devices can see each other. A pair must approve access from both devices before either can connect. Each destination chooses whether to offer a shell. One binary provides the desktop client, user-mode listener, and public relay.

## Build

Install stable Rust and a platform C toolchain, then run `cargo build --locked --release`. The executable is `target/release/massrelay` or `target\release\massrelay.exe` on Windows.

## Start a relay

On a reachable host, initialize the relay's state directory and save the one-use creation ticket printed to stdout.

```sh
massrelay --state-dir ./relay-state relay-init \
  --public-udp 203.0.113.10:4433 --url http://relay.example.com:3340
massrelay --state-dir ./relay-state relay
```

Replace the example public IP and relay URL. The default listener ports are UDP 4433 for authenticated enrollment and membership traffic, and TCP 3340 for the Iroh relay. Enrollment needs the UDP path to be reachable. After enrollment, control requests and shells can use the TCP relay if a direct path is unavailable. For an HTTPS relay URL, terminate TLS in front of the TCP listener with a reverse proxy that supports WebSocket upgrades.

For another pocket network, print the next one-use creation ticket with `massrelay --state-dir ./relay-state relay-ticket`. Keep tickets and state directories private. Anyone holding an unused ticket can redeem it.

## Pair two machines

On the first device, run `massrelay create laptop` and paste the creation ticket on stdin. Then run `massrelay run --allow-shell` and leave it running. Use another terminal to run `massrelay invite`.

On the second device, run `massrelay join workstation` and paste the invite. Run `massrelay run --allow-shell` there too. On each machine approve the other.

```sh
# On laptop
massrelay approve workstation

# On workstation
massrelay approve laptop

# On either side, use the other device's name
massrelay shell laptop
```

Compare the endpoint ID shown by `approve` with the one that `massrelay run` prints on the other device. To script an approval, pass the verified endpoint ID instead of the name.

Use `massrelay peers` to see everyone in the pocket network, recent presence, and your pairing status. Any enrolled device can invite another. Invites can be used once and expire after ten minutes. Use `massrelay decline NAME` to decline or unpair, or `massrelay revoke NAME` to remove another device from the network. Name matching is case-insensitive, and commands accept endpoint IDs as well.

Run `massrelay run` under your ordinary account in a terminal or supervisor of your choice. Use `--allow-shell` on each destination that should accept shells. Approving a peer on such a destination gives that peer the access of the account running MassRelay. Use `--shell /path/to/shell` to override the account's default shell executable, for example to use PowerShell on Windows.

## Connections and state

Iroh authenticates peer keys and encrypts both directions of the shell. It can use direct connections or the configured relay. The relay manages the membership roster, coordinates pair approvals, and can see addressing and presence metadata. Each direct connection requires a locally saved approval for the authenticated peer key on **both** devices. A shell gives the peer access to your local account, including the ability to use that account's MassRelay connections to other devices.

If the relay goes offline, cached approvals still work over a reachable direct path. MassRelay saves peer address candidates, reuses its UDP port when possible, and uses local multicast discovery. Use a fixed `--bind` address and port if a device has a stable direct address you want it to keep. Behind NAT, establishing a new direct path can require the relay. Presence becomes unknown as the last heartbeat ages. Revocations take effect on each device when it next learns about them. A decline closes access locally as soon as you make it and syncs to the relay when it returns.

Keep the device state directory to preserve keys and approvals across restarts. If you lose every enrolled device, initialize a new pocket network using a new creation ticket. A plain shell ends on disconnection. Use the destination's terminal multiplexer if you need work to outlive a connection.

## Verification

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`. On Linux or macOS, run `cargo test --locked shell_works_with_only_a_tcp_relay_path -- --ignored` to test a shell with direct paths disabled. Build the debug binary and run `python3 tests/pocket.py target/debug/massrelay` for the three-device scenario. Both network tests use loopback ports.
