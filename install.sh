#!/bin/sh
set -eu

repo=zorkian/massrelay
install_dir=${MASSRELAY_INSTALL_DIR:-"$HOME/.local/bin"}
version=${MASSRELAY_VERSION:-}
relay=false
public_ip=

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --relay) relay=true ;;
        --public-ip)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail '--public-ip needs an address.'
            public_ip=$2
            shift ;;
        *) fail "Unknown installer option: $1" ;;
    esac
    shift
done
[ -z "$public_ip" ] || "$relay" || fail '--public-ip requires --relay.'

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) printf '%s\n' 'Use the Windows instructions in the MassRelay README.' >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) printf '%s\n' 'No MassRelay binary is available for this CPU.' >&2; exit 1 ;;
esac

if "$relay"; then
    [ "$os" = linux ] || fail '--relay requires Linux with a systemd user manager.'
    systemctl --user show-environment >/dev/null || fail 'Could not reach the systemd user manager.'
    case "$install_dir" in
        /*) ;;
        *) install_dir="$PWD/$install_dir" ;;
    esac
    relay_state=${XDG_DATA_HOME:-"$HOME/.local/share"}/massrelay-relay
    unit_dir=${XDG_CONFIG_HOME:-"$HOME/.config"}/systemd/user
    unit="$unit_dir/massrelay-relay.service"
    [ ! -e "$relay_state/relay.json" ] ||
        fail 'This installer needs a fresh relay directory. Move the previous relay state aside before running it.'
    if [ -e "$unit" ] || [ -L "$unit" ]; then
        saved_ip=$(sed -n 's/^# MassRelay installer public IP: //p' "$unit")
        [ -n "$saved_ip" ] || fail "An existing service uses $unit."
        [ -z "$public_ip" ] || [ "$public_ip" = "$saved_ip" ] ||
            fail "The relay already advertises $saved_ip."
        public_ip=$saved_ip
    fi
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -4fsS --noproxy '*' --proto '=https' https://api.ipify.org ||
            curl -6fsS --noproxy '*' --proto '=https' https://api64.ipify.org) ||
            fail 'Could not discover a public IP. Pass --public-ip ADDRESS.'
    fi
    case "$public_ip" in
        *:*)
            case "$public_ip" in *[!0-9a-fA-F:.]*) fail 'Expected an IPv6 address.' ;; esac
            getent ahostsv6 "$public_ip" >/dev/null || fail 'Expected a usable IPv6 address.'
            advertised="[$public_ip]"
            bind='[::]'
            local_address='[::1]'
            ;;
        *.*)
            case "$public_ip" in *[!0-9.]*) fail 'Expected an IPv4 address.' ;; esac
            printf '%s\n' "$public_ip" | awk -F . '
                NF != 4 { exit 1 }
                { for (i = 1; i <= NF; i++)
                    if ($i !~ /^(0|[1-9][0-9]*)$/ || $i > 255) exit 1 }
            ' || fail 'Expected an IPv4 address.'
            advertised=$public_ip
            bind=0.0.0.0
            local_address=127.0.0.1
            ;;
        *) fail 'Expected a public IPv4 or IPv6 address.' ;;
    esac
fi

asset="massrelay-$os-$arch"
case "$version" in
    '') base="https://github.com/$repo/releases/latest/download" ;;
    v[0-9]*)
        case "$version" in
            *[!a-zA-Z0-9.-]*) printf '%s\n' 'Invalid release tag.' >&2; exit 1 ;;
        esac
        base="https://github.com/$repo/releases/download/$version"
        ;;
    *) printf '%s\n' 'Set MASSRELAY_VERSION to a release tag such as v0.1.0.' >&2; exit 1 ;;
esac

stage=$(mktemp -d "${TMPDIR:-/tmp}/massrelay.XXXXXX")
destination_tmp=
unit_tmp=
cleanup() {
    rm -f "$stage/$asset" "$stage/SHA256SUMS" "$stage/massrelay-relay.service"
    rmdir "$stage"
    if [ -n "$destination_tmp" ]; then
        rm -f "$destination_tmp"
    fi
    if [ -n "$unit_tmp" ]; then
        rm -f "$unit_tmp"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if "$relay"; then
    # Escape systemd quoting, specifiers, and ExecStart variable expansion.
    unit_arg() {
        printf '"%s"' "$(printf '%s' "$1" | sed 's/["\\]/\\&/g; s/%/%%/g; s/\$/$$/g')"
    }
    {
        printf '# MassRelay installer public IP: %s\n' "$public_ip"
        printf '[Unit]\nDescription=MassRelay relay\n\n'
        printf '[Service]\nType=exec\nRestart=on-failure\nExecStart='
        unit_arg "$install_dir/massrelay"
        printf ' --state-dir '
        unit_arg "$relay_state"
        printf ' relay --udp-bind "%s:4433" --relay-bind "%s:3340"\n' "$bind" "$bind"
        printf '\n[Install]\nWantedBy=default.target\n'
    } > "$stage/massrelay-relay.service"
    if [ -e "$unit" ] || [ -L "$unit" ]; then
        cmp -s "$unit" "$stage/massrelay-relay.service" ||
            fail "The existing service at $unit differs from this installation."
    fi
fi

if curl -fsSL "$base/$asset" -o "$stage/$asset" 2>/dev/null; then
    curl -fsSL "$base/SHA256SUMS" -o "$stage/SHA256SUMS"
else
    if ! command -v gh >/dev/null 2>&1; then
        printf '%s\n' 'Download failed. For a private release, sign in with GitHub CLI and try again.' >&2
        exit 1
    fi
    if [ -n "$version" ]; then
        set -- "$version"
    else
        set --
    fi
    gh release download "$@" --repo "$repo" --pattern "$asset" --pattern SHA256SUMS --dir "$stage" --clobber
fi

checksum=$(awk -v name="$asset" '$2 == name { print $1 }' "$stage/SHA256SUMS")
if [ "${#checksum}" -ne 64 ]; then
    printf '%s\n' "Missing or malformed checksum for $asset." >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum < "$stage/$asset")
else
    actual=$(shasum -a 256 < "$stage/$asset")
fi
if [ "${actual%% *}" != "$checksum" ]; then
    printf '%s\n' "Checksum verification failed for $asset." >&2
    exit 1
fi

mkdir -p "$install_dir"
if [ -d "$install_dir/massrelay" ]; then
    printf '%s\n' "Cannot replace directory $install_dir/massrelay." >&2
    exit 1
fi
destination_tmp=$(mktemp "$install_dir/.massrelay.XXXXXX")
install -m 0755 "$stage/$asset" "$destination_tmp"
if "$relay"; then
    "$destination_tmp" relay-grants --help >/dev/null 2>&1 ||
        fail 'Choose a MassRelay release with encrypted membership for --relay.'
    if [ ! -e "$relay_state/private-relay.json" ]; then
        locator=$("$destination_tmp" --state-dir "$relay_state" relay-init \
            --public-udp "$advertised:4433" --url "http://$advertised:3340")
        printf 'Relay locator (keep secret): %s\n' "$locator"
    fi
fi
mv -f "$destination_tmp" "$install_dir/massrelay"
destination_tmp=
printf 'Installed %s\n' "$install_dir/massrelay"

if "$relay"; then
    mkdir -p "$unit_dir"
    if [ ! -e "$unit" ] && [ ! -L "$unit" ]; then
        unit_tmp=$(mktemp "$unit_dir/.massrelay-relay.XXXXXX")
        install -m 0644 "$stage/massrelay-relay.service" "$unit_tmp"
        mv -f "$unit_tmp" "$unit"
        unit_tmp=
    fi
    systemctl --user daemon-reload
    systemctl --user enable massrelay-relay.service
    systemctl --user restart massrelay-relay.service
    for attempt in $(seq 1 30); do
        if curl -fsS --max-time 2 --noproxy '*' -o /dev/null "http://$local_address:3340/healthz" 2>/dev/null; then
            break
        fi
        systemctl --user is-active --quiet massrelay-relay.service ||
            fail 'Relay startup failed. Check journalctl --user -u massrelay-relay.service.'
        sleep 1
    done
    curl -fsS --max-time 2 --noproxy '*' -o /dev/null "http://$local_address:3340/healthz" ||
        fail 'Relay did not become ready. Check journalctl --user -u massrelay-relay.service.'
    systemctl --user is-active --quiet massrelay-relay.service ||
        fail 'Relay stopped. Check journalctl --user -u massrelay-relay.service.'
    if [ "$(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null || true)" != yes ]; then
        printf '%s\n' 'For boot startup and operation after logout, enable lingering for this user.'
    fi
fi

case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf 'Add %s to PATH to run massrelay by name.\n' "$install_dir" ;;
esac
