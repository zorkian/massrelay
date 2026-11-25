#!/bin/sh
set -eu

repo=zorkian/massrelay
install_dir=${MASSRELAY_INSTALL_DIR:-"$HOME/bin"}
version=${MASSRELAY_VERSION:-}

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
cleanup() {
    rm -f "$stage/$asset" "$stage/SHA256SUMS"
    rmdir "$stage"
    if [ -n "$destination_tmp" ]; then
        rm -f "$destination_tmp"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

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
mv -f "$destination_tmp" "$install_dir/massrelay"
destination_tmp=
printf 'Installed %s\n' "$install_dir/massrelay"

case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf 'Add %s to PATH to run massrelay by name.\n' "$install_dir" ;;
esac
