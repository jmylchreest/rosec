#!/usr/bin/env python3
"""Generate build-time trust entries from final, unmodified provider artifacts.

Each --bundle takes the built WASM, its policy, and the absolute install path.
The output contains public hashes only. It is embedded in the host, never read
as a runtime trust file. Run after any WASM stripping/optimisation.
"""

import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", nargs=3, action="append", required=True,
                        metavar=("WASM", "POLICY", "INSTALLED_PATH"))
    args = parser.parse_args()
    entries = []
    paths = set()
    for wasm, policy, installed in args.bundle:
        if not Path(installed).is_absolute() or ".." in Path(installed).parts:
            parser.error(f"install path must be absolute without '..': {installed}")
        if installed in paths:
            parser.error(f"duplicate install path: {installed}")
        paths.add(installed)
        entries.append({
            "path": installed,
            "wasm_sha256": hashlib.sha256(Path(wasm).read_bytes()).hexdigest(),
            "policy_sha256": hashlib.sha256(Path(policy).read_bytes()).hexdigest(),
        })
    print(json.dumps(sorted(entries, key=lambda entry: entry["path"]), indent=2))


if __name__ == "__main__":
    main()
