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

# Latest stable tag (used to calculate next release version)
_latest_tag := `git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || echo "v0.0.0"`

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
  TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || echo "v0.0.0")
  TAG="${TAG#v}"
  MAJOR=$(echo "$TAG" | cut -d. -f1)
  MINOR=$(echo "$TAG" | cut -d. -f2)
  PATCH=$(echo "$TAG" | cut -d. -f3 | cut -d- -f1)
  echo "${MAJOR}.${MINOR}.$((PATCH + 1))"
`

_next_minor := `
  TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || echo "v0.0.0")
  TAG="${TAG#v}"
  MAJOR=$(echo "$TAG" | cut -d. -f1)
  MINOR=$(echo "$TAG" | cut -d. -f2)
  echo "${MAJOR}.$((MINOR + 1)).0"
`

_next_major := `
  TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || echo "v0.0.0")
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

  echo "Current version:  {{ cargo_version }}"
  echo "Releasing:        ${VERSION}  (tag: v${VERSION})"
  echo ""

  if [[ "$PUSH" == "push" ]]; then
    echo "Mode: EXECUTE + PUSH — this will commit, tag, and push to origin"
    echo ""
    cargo release "${VERSION}" --execute --no-confirm
    git push --follow-tags origin HEAD
    echo ""
    echo "Pushed v${VERSION} — GHA release workflow will now build and publish."
  else
    echo "Mode: DRY-RUN — no changes will be made (pass 'push' to execute)"
    echo ""
    cargo release "${VERSION}"
  fi
