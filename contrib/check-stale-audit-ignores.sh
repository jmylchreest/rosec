#!/usr/bin/env bash
# Fail if any accepted advisory no longer matches the lockfiles.
#
# `cargo audit` filters ignored advisories out of its output entirely, so an
# exemption whose upstream fix has landed looks identical to one still doing
# work. Re-run the audit with the ignore list out of scope and diff the two
# sets: anything we exempt that no longer matches is dead and should go, along
# with whatever issue tracks it.
#
# cargo-audit only reads a cwd-local .cargo/audit.toml, so running from a
# scratch directory with --file is what takes the exemptions out of scope.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

# Advisory ids accepted for the root workspace.
mapfile -t ignored < <(grep -oE '"RUSTSEC-[0-9]{4}-[0-9]{4}"' .cargo/audit.toml | tr -d '"' | sort -u)

# Advisory ids accepted for the WASM provider crates, which carry their own
# lockfiles and get their exemptions passed on the command line.
mapfile -t wasm_ignored < <(grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' .github/workflows/audit.yml | sort -u)

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# All advisory ids matching a lockfile, exemptions not applied.
# cargo audit exits non-zero whenever it finds anything, which is the normal
# case here — we want its report, not its verdict.
matched() {
  (cd "$scratch" && cargo audit --file "$1" --json 2>/dev/null || true) |
    python3 -c '
import json, sys

def ids(node):
    """Yield every advisory id anywhere in the report.

    The shape varies by cargo-audit version and by whether a section is empty
    (absent, null, list, or dict), so walk it rather than indexing into it.
    """
    if isinstance(node, dict):
        adv = node.get("advisory")
        if isinstance(adv, dict) and isinstance(adv.get("id"), str):
            yield adv["id"]
        for v in node.values():
            yield from ids(v)
    elif isinstance(node, list):
        for v in node:
            yield from ids(v)

try:
    doc = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(0)
print("\n".join(sorted(set(ids(doc)))))
'
}

stale=0

root_matched=$(matched "$repo_root/Cargo.lock")
for id in "${ignored[@]}"; do
  if ! grep -qx "$id" <<<"$root_matched"; then
    echo "STALE: $id is exempted in .cargo/audit.toml but no longer matches Cargo.lock"
    stale=1
  fi
done

wasm_matched=""
for crate in rosec-bitwarden-pm rosec-bitwarden-sm rosec-gnome-keyring rosec-keepassxc-file; do
  [[ -f "$crate/Cargo.lock" ]] || continue
  wasm_matched+=$'\n'$(matched "$repo_root/$crate/Cargo.lock")
done
for id in "${wasm_ignored[@]}"; do
  if ! grep -qx "$id" <<<"$wasm_matched"; then
    echo "STALE: $id is exempted in .github/workflows/audit.yml but matches no WASM crate lockfile"
    stale=1
  fi
done

if (( stale )); then
  echo
  echo "Remove the exemption(s) above and close the issue tracking them."
  exit 1
fi

echo "All audit exemptions still apply."
