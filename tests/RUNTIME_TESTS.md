# Mounted FUSE and prompt GUI checks

These opt-in checks use fixture data and isolated temporary resources. They do
not use the running daemon's providers or the user's desktop display.

For the mounted SSH/TOTP tests, the host must provide `/dev/fuse` and
`fusermount3`. The tests create private mounts and unmount them on drop:

```sh
cargo test -p rosecd mounted_fuse_ -- --ignored
```

They exercise actual reads, read-only enforcement, revocation through an already
open file descriptor, rejection of a pending stale rebuild, and fresh unlock.
They run the real managers with deterministic provider fixtures.

The GUI test requires Xvfb, libX11, libXtst, ImageMagick `import`, and
`dbus-run-session`. Build the prompt, then run:

```sh
cargo build -p rosec-prompt
dbus-run-session -- python3 tests/gui_prompt_smoke.py \
  --binary "$PWD/target/debug/rosec-prompt" \
  --output /tmp/rosec-gui-results
```

Adjust the binary path when using `CARGO_TARGET_DIR`. The script creates a
private X11 server, enters synthetic credentials, checks JSON and exit status,
and captures screenshots. Cases cover password masking, multiple fields and Tab
focus, cancellation, confirmation, OTP entry, incomplete OTP rejection and
passkey selection. Screenshots contain fixture values only.

This does not exercise a native Wayland compositor, desktop screenshot portals,
physical authenticators, or live cloud accounts. No product code is changed by
these tests.
