# Changelog

## Unreleased

### Potentially breaking for packagers

PAM auto-unlock and password-change sync now require the PAM helper to identify a trusted installed `rosecd` executable. The default search covers `/usr/bin/rosecd` and `bin/rosecd` in the helper’s own installation prefix. Split packages or custom layouts outside those defaults should rebuild `rosec-pam-unlock` with `ROSEC_PAM_DAEMON_PATH` set to a comma-separated list of absolute or helper-relative daemon paths. User-writable daemon installations require manual vault unlock. OS login continues if the daemon cannot be verified. See the [packagers guide](docs/docs/developers/packagers.md).
