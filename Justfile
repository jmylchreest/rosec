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
  cargo build --release --locked --bin rosecd --bin rosec

# Build WASM provider plugins (requires wasm32-wasip1 target)
build-wasm:
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-bitwarden-pm/Cargo.toml
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-bitwarden-sm/Cargo.toml
  cargo build --target wasm32-wasip1 --release --manifest-path rosec-gnome-keyring/Cargo.toml

# Run all tests
test:
  cargo test --workspace --locked

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
