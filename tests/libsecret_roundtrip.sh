#!/usr/bin/env bash
# Run from the worktree root; requires cc, pkg-config, libsecret and dbus-daemon.
set -euo pipefail
fixture=$(mktemp -d /tmp/rosec-libsecret.XXXXXX)
trap 'rm -rf "$fixture"' EXIT
cc -Wall -Wextra -Werror tests/libsecret_roundtrip.c $(pkg-config --cflags --libs libsecret-1) -o "$fixture/client"
export ROSEC_LIBSECRET_CLIENT="$fixture/client"
export ROSEC_LIBSECRET_FIXTURE="$fixture"
cargo test -p rosec-secret-service --test libsecret_roundtrip -- --ignored --nocapture
