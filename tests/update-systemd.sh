#!/bin/sh
# Native acceptance for 'massrelay update' against the systemd user manager.
#
#     cargo build
#     tests/update-systemd.sh target/debug/massrelay
#
# Everything is disposable: a temporary state directory with an offline fixture profile, a
# temporary copy of the program, and that profile's own unit (massrelay-client-<hash>.service),
# all removed on exit. No other unit and no existing profile is touched. The release download
# is not exercised; the exchange, the manager's restart policy and the rollback are, with a
# real runtime process under the real manager.
set -eu

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

binary=${1:-target/debug/massrelay}
[ -x "$binary" ] || fail "Build massrelay first: $binary is not an executable."
if ! systemctl --user show-environment >/dev/null 2>&1; then
    printf '%s\n' 'No systemd user manager is reachable here; nothing was run.' >&2
    exit 77
fi
unset MASSRELAY_STATE_DIR MASSRELAY_RELAY

root=$(mktemp -d "${TMPDIR:-/tmp}/massrelay-update-acceptance.XXXXXX")
root=$(cd "$root" && pwd -P)
state="$root/state"
bin="$root/bin"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit="massrelay-client-$(printf '%s' "$state" | sha256sum | cut -d ' ' -f 1).service"

cleanup() {
    systemctl --user disable --now "$unit" >/dev/null 2>&1 || true
    rm -f "$units/$unit"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    systemctl --user reset-failed "$unit" >/dev/null 2>&1 || true
    rm -rf "$root"
}
[ ! -e "$units/$unit" ] && [ ! -L "$units/$unit" ] || fail "A unit named $unit already exists."

trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -m 700 "$state"
mkdir -m 755 "$bin"
install -m 755 "$binary" "$bin/massrelay"

# An enrolled profile whose relay is an unused loopback port: its runtime serves offline.
MASSRELAY_FIXTURE_STATE_DIR="$state" \
    cargo test --locked --offline write_an_offline_fixture_profile -- --ignored >/dev/null

"$bin/massrelay" --state-dir "$state" install
[ -f "$units/$unit" ] || fail "The disposable service was not installed as $unit."

MASSRELAY_ACCEPTANCE_STATE_DIR="$state" MASSRELAY_ACCEPTANCE_PROGRAM="$bin/massrelay" \
    cargo test --locked --offline a_disposable_systemd_service_is_updated_and_reverted \
    -- --ignored --nocapture --test-threads=1
printf '%s\n' 'Updater acceptance against systemd passed.'
