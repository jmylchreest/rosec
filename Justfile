# rosec Justfile
# https://just.systems
#
# Common tasks:
#   just build        Build debug binaries
#   just test         Run tests
#   just lint         Run clippy + fmt check
#   just version      Show current version info
#   just release-patch  Bump patch, commit, tag (dry-run)
#   just release-patch push  ...then push to trigger GHA release

set shell := ["bash", "-euo", "pipefail", "-c"]

# ---------------------------------------------------------------------------
# Version derivation — mirrors release.yml prepare job exactly.
#
# Snapshot (no tag or commits ahead of tag):
#   version     = {major}.{minor}.{next_patch}-dev.{commits}+{hash}
#   version_tag = v{major}.{minor}.{next_patch}-dev.{commits}
#
# On exact tag (0 commits ahead):
#   version     = {major}.{minor}.{patch}        (from Cargo.toml)
#   version_tag = v{major}.{minor}.{patch}
#
# The '+hash' build metadata is valid semver but omitted from git tags
# because GitHub does not allow '+' in tag names.
# ---------------------------------------------------------------------------

# Current version from workspace Cargo.toml (the authoritative source for releases)
cargo_version := `cargo metadata --no-deps --format-version 1 | python3 -c "import json,sys; ws=json.load(sys.stdin); print(next(p['version'] for p in ws['packages'] if p['name']=='rosecd'))"`

# Git-derived snapshot version (matches GHA logic)
_describe := `git describe --tags --always --long 2>/dev/null || echo ""`
_sha      := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`

version := `
  DESCRIBE=$(git describe --tags --always --long 2>/dev/null || echo "")
  SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
  if [[ "$DESCRIBE" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)-g([a-f0-9]+)$ ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    COMMITS="${BASH_REMATCH[4]}"
    HASH="${BASH_REMATCH[5]}"
    if [[ "$COMMITS" == "0" ]]; then
      echo "${MAJOR}.${MINOR}.${PATCH}"
    else
      NEXT_PATCH=$((PATCH + 1))
      echo "${MAJOR}.${MINOR}.${NEXT_PATCH}-dev.${COMMITS}+${HASH}"
    fi
  else
    echo "0.0.0-dev.0+${SHA}"
  fi
`

version_tag := `
  DESCRIBE=$(git describe --tags --always --long 2>/dev/null || echo "")
  SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
  if [[ "$DESCRIBE" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)-g([a-f0-9]+)$ ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    COMMITS="${BASH_REMATCH[4]}"
    if [[ "$COMMITS" == "0" ]]; then
      echo "v${MAJOR}.${MINOR}.${PATCH}"
    else
      NEXT_PATCH=$((PATCH + 1))
      echo "v${MAJOR}.${MINOR}.${NEXT_PATCH}-dev.${COMMITS}"
    fi
  else
    echo "v0.0.0-dev.0"
  fi
`

# Latest stable tag reachable from main (used to calculate next release version).
# Tags reachable only from feature branches are intentionally ignored — the
# release base is whatever shipped on main, not whatever is tagged anywhere.
_latest_tag := `git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' main 2>/dev/null || echo "v0.0.0"`

# ---------------------------------------------------------------------------
# Default: list available recipes
# ---------------------------------------------------------------------------

[private]
default:
  @just --list

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------

# Build debug binaries
build:
  cargo build --workspace

# Build release binaries (native only)
build-release:
  cargo build --release --locked \
    --bin rosec \
    --bin rosecd \
    --bin rosec-prompt \
    --bin rosec-pam-unlock

# Build WASM provider plugins (requires wasm32-wasip1 target)
build-wasm:
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-bitwarden-pm/Cargo.toml
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-bitwarden-sm/Cargo.toml
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-gnome-keyring/Cargo.toml
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-keepassxc-file/Cargo.toml

# Run all tests
test:
  cargo test --workspace --locked

# profile-build emits target/profiling/rosecd: release-optimised with
# line-table debug info, suitable for samply / perf / heaptrack. Runtime
# cost vs the plain `release` profile is unmeasurable.

# Build rosecd at release-speed with profiling symbols (target/profiling/)
profile-build:
  cargo build --profile=profiling -p rosecd

# console-build emits the same with the `console` feature, enabling
# console-subscriber so tokio-console can attach. RUSTFLAGS=--cfg
# tokio_unstable is set automatically. Runtime cost: ~5-10 % per task —
# fine for diagnosis, don't ship.

# Build rosecd with tokio-console support (target/profiling/, --features=console)
console-build:
  RUSTFLAGS="--cfg tokio_unstable" cargo build --profile=profiling -p rosecd --features=console

# profile-record attaches samply to the running rosecd for `duration`
# seconds (default 30). Runs samply under sudo because rosecd sets
# PR_SET_DUMPABLE=0; without root the kernel refuses ptrace_may_access.
# Output opens in the Firefox profiler.
#
#   just profile-record         # 30 s
#   just profile-record 60      # 60 s

# Sample CPU of running rosecd via samply (sudo) for DURATION seconds
profile-record duration="30":
  #!/usr/bin/env bash
  set -euo pipefail
  PID=$(pgrep -x rosecd || true)
  if [[ -z "$PID" ]]; then
    echo "error: rosecd is not running" >&2
    exit 1
  fi
  # Resolve samply against the caller's PATH (sudo strips PATH, so plain
  # `sudo samply` would fail when samply lives in ~/.cargo/bin).
  SAMPLY=$(command -v samply || true)
  if [[ -z "$SAMPLY" ]]; then
    echo "error: 'samply' not found in PATH — install with: cargo install samply" >&2
    exit 1
  fi
  echo "Recording rosecd (PID $PID) for {{ duration }}s …"
  sudo "$SAMPLY" record -p "$PID" --duration "{{ duration }}"

# sign-wasm signs the .wasm + .wasm.policy.toml pairs with WASM_SIGNING_KEY
# and stages the result (incl. .wasm.minisig) under dist/providers/ — same
# layout the release workflow ships. The .minisig covers
# (wasm_bytes || policy_bytes), so substituting either file invalidates it.
#
# Copy dist/providers/* to your provider install dir to exercise the
# wasm_verify = "required" code path locally.
#
# Requires:
#   - WASM_SIGNING_KEY env var: contents of an rsign/minisign secret-key file
#   - rsign2 in PATH (cargo install rsign2)
#   - 'just build-wasm' has produced the .wasm artefacts

# Sign + stage WASM providers (uses WASM_SIGNING_KEY env var)
sign-wasm:
  #!/usr/bin/env bash
  set -euo pipefail

  if [[ -z "${WASM_SIGNING_KEY:-}" ]]; then
    echo "error: WASM_SIGNING_KEY is not set." >&2
    echo "" >&2
    echo "Set it to the contents of an rsign/minisign secret-key file:" >&2
    echo "  export WASM_SIGNING_KEY=\"\$(cat path/to/rosec-wasm-signing.key)\"" >&2
    echo "  just sign-wasm" >&2
    echo "" >&2
    echo "The corresponding public key is embedded in" >&2
    echo "rosec-wasm/src/keys/mod.rs (WASM_SIGNING_PUBKEY)." >&2
    exit 1
  fi

  if ! command -v rsign >/dev/null 2>&1; then
    echo "error: 'rsign' not found in PATH — install with: cargo install rsign2" >&2
    exit 1
  fi

  KEYFILE=$(mktemp)
  trap 'rm -f "${KEYFILE}"' EXIT
  printf '%s' "${WASM_SIGNING_KEY}" > "${KEYFILE}"

  install -d -m 755 dist/providers

  for crate in {{ _wasm_crates }}; do
    stem="${crate//-/_}"
    wasm_src="${crate}/target/wasm32-wasip1/release/${stem}.wasm"
    policy_src="${crate}/${stem}.wasm.policy.toml"

    if [[ ! -f "${wasm_src}" ]]; then
      echo "error: ${wasm_src} not found — run 'just build-wasm' first" >&2
      exit 1
    fi
    if [[ ! -f "${policy_src}" ]]; then
      echo "error: ${policy_src} not found — provider crate is missing its policy" >&2
      exit 1
    fi

    wasm_dst="dist/providers/${stem}.wasm"
    policy_dst="dist/providers/${stem}.wasm.policy.toml"
    sig_dst="dist/providers/${stem}.wasm.minisig"

    install -m 644 "${wasm_src}" "${wasm_dst}"
    install -m 644 "${policy_src}" "${policy_dst}"

    combined=$(mktemp)
    cat "${wasm_dst}" "${policy_dst}" > "${combined}"
    rsign sign -s "${KEYFILE}" -W "${combined}"
    mv "${combined}.minisig" "${sig_dst}"
    rm -f "${combined}"

    echo "signed: ${wasm_dst} (+ ${policy_dst##*/}, ${sig_dst##*/})"
  done

  echo ""
  echo "Output staged in dist/providers/ — to test wasm_verify = \"required\":"
  echo "  install -d -m 755 \"{{ _plugin_dir }}\""
  echo "  install -m 644 dist/providers/* \"{{ _plugin_dir }}/\""
  echo "  systemctl --user restart rosecd"

# ---------------------------------------------------------------------------
# User-local install (no sudo)
#
# Layout:
#   binaries → $XDG_BIN_HOME (default ~/.local/bin)
#   plugins  → $XDG_DATA_HOME/rosec/providers/  (default ~/.local/share/...)
#
# Recipes:
#   just install         build everything + install binaries + plugins
#   just install-bin     just the native binaries
#   just install-wasm    just the WASM plugin .wasm files
#   just uninstall       remove everything we'd install
# ---------------------------------------------------------------------------

# Resolved install directories.
_bin_dir := env_var_or_default("XDG_BIN_HOME", env_var_or_default("HOME", "") + "/.local/bin")
_data_dir := env_var_or_default("XDG_DATA_HOME", env_var_or_default("HOME", "") + "/.local/share")
_plugin_dir := _data_dir + "/rosec/providers"

# Native binaries we ship.  rosec-pam-unlock comes from the rosec-pam crate.
_bins := "rosec rosecd rosec-prompt rosec-pam-unlock"

# WASM plugins (manifest-path, lowercase artifact stem).  Kept in lockstep
# with build-wasm.
_wasm_crates := "rosec-bitwarden-pm rosec-bitwarden-sm rosec-gnome-keyring rosec-keepassxc-file"

# Full install: binaries + plugins.  Builds first if artifacts are stale.
install: build-release build-wasm install-bin install-wasm
  @echo ""
  @echo "Installed to:"
  @echo "  binaries: {{ _bin_dir }}"
  @echo "  plugins:  {{ _plugin_dir }}"
  @echo ""
  @echo "Make sure $HOME/.local/bin is on your PATH."

# Install just the native binaries.
install-bin:
  #!/usr/bin/env bash
  set -euo pipefail
  install -d -m 755 "{{ _bin_dir }}"
  for bin in {{ _bins }}; do
    src="target/release/${bin}"
    if [[ ! -x "$src" ]]; then
      echo "error: ${src} not found — run 'just build-release' first" >&2
      exit 1
    fi
    install -m 755 "$src" "{{ _bin_dir }}/${bin}"
    echo "installed: {{ _bin_dir }}/${bin}"
  done

# Install just the WASM plugin .wasm files.
install-wasm:
  #!/usr/bin/env bash
  set -euo pipefail
  install -d -m 755 "{{ _plugin_dir }}"
  for crate in {{ _wasm_crates }}; do
    stem="${crate//-/_}"
    src="${crate}/target/wasm32-wasip1/release/${stem}.wasm"
    if [[ ! -f "$src" ]]; then
      echo "error: ${src} not found — run 'just build-wasm' first" >&2
      exit 1
    fi
    install -m 644 "$src" "{{ _plugin_dir }}/${stem}.wasm"
    echo "installed: {{ _plugin_dir }}/${stem}.wasm"
  done

# Remove everything install would have placed.
uninstall:
  #!/usr/bin/env bash
  set -euo pipefail
  for bin in {{ _bins }}; do
    f="{{ _bin_dir }}/${bin}"
    if [[ -e "$f" ]]; then rm -v -- "$f"; fi
  done
  for crate in {{ _wasm_crates }}; do
    stem="${crate//-/_}"
    f="{{ _plugin_dir }}/${stem}.wasm"
    if [[ -e "$f" ]]; then rm -v -- "$f"; fi
  done
  echo "done — config in \$XDG_CONFIG_HOME/rosec/ left untouched"

# Run clippy (warnings as errors) + fmt check
lint:
  cargo clippy --workspace --locked -- -D warnings
  cargo fmt --all -- --check

# Run clippy + fmt check, auto-fix fmt
lint-fix:
  cargo clippy --workspace --locked -- -D warnings
  cargo fmt --all

# Check compilation without building
check:
  cargo check --workspace

# Show current version information
version:
  @echo "Cargo version:  {{ cargo_version }}"
  @echo "Git version:    {{ version }}"
  @echo "Git tag:        {{ version_tag }}"
  @echo "Latest tag:     {{ _latest_tag }}"
  @echo "Commit:         {{ _sha }}"

# ---------------------------------------------------------------------------
# Release
#
# The release recipes use cargo-release to bump the version in
# [workspace.package], create a signed commit and tag, then optionally push.
#
# Install: cargo install cargo-release
#
# Dry-run (default) — inspect what will happen:
#   just release-patch
#   just release-minor
#   just release-major
#   just release-rc
#   just release 1.2.3
#
# Execute + push (triggers GHA release workflow):
#   just release-patch push
#   just release 1.2.3 push
# ---------------------------------------------------------------------------

# Calculate next patch/minor/major versions from latest tag
_next_patch := `
  TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' main 2>/dev/null || echo "v0.0.0")
  TAG="${TAG#v}"
  MAJOR=$(echo "$TAG" | cut -d. -f1)
  MINOR=$(echo "$TAG" | cut -d. -f2)
  PATCH=$(echo "$TAG" | cut -d. -f3 | cut -d- -f1)
  echo "${MAJOR}.${MINOR}.$((PATCH + 1))"
`

_next_minor := `
  TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' main 2>/dev/null || echo "v0.0.0")
  TAG="${TAG#v}"
  MAJOR=$(echo "$TAG" | cut -d. -f1)
  MINOR=$(echo "$TAG" | cut -d. -f2)
  echo "${MAJOR}.$((MINOR + 1)).0"
`

_next_major := `
  TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' main 2>/dev/null || echo "v0.0.0")
  TAG="${TAG#v}"
  MAJOR=$(echo "$TAG" | cut -d. -f1)
  echo "$((MAJOR + 1)).0.0"
`

# Bump patch version (e.g. 0.0.1 → 0.0.2). Pass 'push' to push after tagging.
release-patch push="":
  @just _release "{{ _next_patch }}" "{{ push }}"

# Bump minor version (e.g. 0.0.1 → 0.1.0). Pass 'push' to push after tagging.
release-minor push="":
  @just _release "{{ _next_minor }}" "{{ push }}"

# Bump major version (e.g. 0.0.1 → 1.0.0). Pass 'push' to push after tagging.
release-major push="":
  @just _release "{{ _next_major }}" "{{ push }}"

# Cut a release candidate (e.g. just release-rc 0.1.0). Pass 'push' to push.
release-rc version push="":
  @just _release "{{ version }}-rc.1" "{{ push }}"

# Cut a release with an explicit version (e.g. just release 1.2.3). Pass 'push' to push.
release version push="":
  @just _release "{{ version }}" "{{ push }}"

# Internal: run cargo-release for a given version, optionally push
[private]
_release version push="":
  #!/usr/bin/env bash
  set -euo pipefail
  VERSION="{{ version }}"
  PUSH="{{ push }}"

  CARGO_VER="{{ cargo_version }}"
  MAIN_TAG_VER="$(echo '{{ _latest_tag }}' | sed 's/^v//')"

  echo "Cargo.toml:       ${CARGO_VER}"
  echo "Latest tag(main): {{ _latest_tag }}"
  echo "Releasing:        ${VERSION}  (tag: v${VERSION})"
  echo ""

  if [[ "${CARGO_VER}" != "${MAIN_TAG_VER}" ]]; then
    echo "ERROR: Cargo.toml (${CARGO_VER}) and latest tag on main (${MAIN_TAG_VER}) disagree."
    echo ""
    echo "Likely causes:"
    echo "  - A previous release tag points at an orphan commit (rebased into main"
    echo "    under a different SHA), so 'git describe main' can't see it."
    echo "  - Cargo.toml was bumped without a release tag, or vice versa."
    echo ""
    echo "Resolution:"
    echo "  1. If main contains an equivalent 'chore: release vX.Y.Z' commit at a"
    echo "     different SHA, retarget the tag at that commit:"
    echo "       git log --oneline main | grep 'chore: release v${CARGO_VER}'"
    echo "       git tag -f v${CARGO_VER} <main-commit-sha>"
    echo "       git push origin v${CARGO_VER} --force   # only if origin needs it"
    echo "  2. If Cargo.toml is wrong, set [workspace.package].version to match"
    echo "     the latest tag and commit."
    echo "  3. If the missing release commit was never landed on main, cherry-pick"
    echo "     it onto main first, then retag."
    echo ""
    exit 1
  fi


  if [[ "$PUSH" == "push" ]]; then
    echo "Mode: EXECUTE + PUSH — this will commit, tag, and push to origin"
    echo ""
    cargo release "${VERSION}" --execute --no-confirm
    # Push branch and tag separately so GitHub fires distinct workflow events.
    # --follow-tags in a single push can cause GitHub to only trigger for the
    # branch ref, which then skips (it sees the tag on HEAD). The tag ref
    # never gets its own workflow run.
    git push origin HEAD
    git push origin "v${VERSION}"
    echo ""
    echo "Pushed v${VERSION} — GHA release workflow will now build and publish."
  else
    echo "Mode: DRY-RUN — no changes will be made (pass 'push' to execute)"
    echo ""
    cargo release "${VERSION}"
  fi
