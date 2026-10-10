#!/usr/bin/env python3
"""Produce GPL corresponding source and notices for the standalone WASM guest.

Run from a committed checkout. Never reads credentials or signing keys.
The binary itself is signed/packaged by rosec-package-wasm in release.yml.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.version or any(c not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+-_" for c in args.version):
        parser.error("invalid version")
    root = Path(__file__).resolve().parents[1]
    guest = root / "rosec-protonpass"
    if run("git", "status", "--porcelain", cwd=root).strip():
        raise SystemExit("Commit source changes before packaging corresponding source")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    notices = output / "notices"
    notices.mkdir(exist_ok=True)
    for name in ("LICENSE", "UPSTREAM.txt", "DISTRIBUTION.md"):
        shutil.copyfile(guest / name, notices / name)
    metadata = json.loads(run("cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", "wasm32-wasip1", cwd=guest))
    tree = run("cargo", "tree", "--locked", "--offline", "--target", "wasm32-wasip1", "--edges", "normal,build", "--prefix", "none", "--format", "{p}", cwd=guest)
    linked = {tuple(line.split()[:2]) for line in tree.splitlines()}
    inventory = []
    # Explicit reviewed expressions. A new dependency/licence must be reviewed,
    # rather than silently included in a release using an optimistic fallback.
    allowed = {"MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0-or-later",
        "MIT OR Apache-2.0", "Apache-2.0 OR MIT", "MIT/Apache-2.0",
        "Zlib OR Apache-2.0 OR MIT", "Unlicense OR MIT",
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"}
    for package in metadata["packages"]:
        if (package["name"], "v" + package["version"]) not in linked:
            continue
        if package["license"] not in allowed:
            raise SystemExit(f"Unreviewed licence: {package['name']} {package['license']}")
        directory = Path(package["manifest_path"]).parent
        dest = notices / (package["name"] + "-" + package["version"])
        files = [p for p in (directory.iterdir() if package["name"] == "rosec-protonpass" else directory.rglob("*")) if p.is_file() and p.name.lower().startswith(("license", "licence", "copying", "notice", "copyright"))]
        if not files and package["version"] == "1.41.0" and package["name"] in {
            "extism-convert", "extism-convert-macros", "extism-manifest"
        }:
            # These published crates omit the workspace licence. Preserve the
            # exact pinned upstream text and its provenance, never guess a text
            # from an SPDX expression or silently permit future versions.
            directory = guest / "notices/extism-1.41.0"
            licence = directory / "LICENSE"
            if hashlib.sha256(licence.read_bytes()).hexdigest() != "d01e60805075b591cbecc63b8582788e54e190f699037f1af19fb5294b7a47ab":
                raise SystemExit("Pinned Extism licence checksum mismatch")
            files = [licence, directory / "PROVENANCE.txt"]
        if not files:
            raise SystemExit(f"Missing licence text: {package['name']}")
        for path in files:
            target = dest / path.relative_to(directory)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        inventory.append({k: package[k] for k in ("name", "version", "license", "repository")})
    (notices / "dependencies.json").write_text(json.dumps(inventory, indent=2) + "\n")
    commit = run("git", "rev-parse", "HEAD", cwd=root).strip()
    (notices / "SOURCE.txt").write_text(f"Source commit: {commit}\nCorresponding source: rosec-provider-protonpass-{args.version}.source.tar.gz\nPublished alongside the WASM archive in the same release.\n")
    # Work below output rather than /tmp: vendored build/test dependencies can
    # exceed small temporary filesystems. Include the full tracked source tree
    # since native test dependencies use workspace-inherited declarations.
    with tempfile.TemporaryDirectory(prefix="proton-source-", dir=output) as temporary:
        source = Path(temporary)
        archive = source / "tree.tar"
        subprocess.run(["git", "archive", "--format=tar", "-o", str(archive), "HEAD"], cwd=root, check=True)
        with tarfile.open(archive) as tar:
            tar.extractall(source, filter="data")
        archive.unlink()
        vendor_config = run("cargo", "vendor", "--locked", "--offline", "--versioned-dirs", str(source / "vendor"), cwd=guest)
        config = source / "rosec-protonpass/.cargo/config.toml"
        config.parent.mkdir(exist_ok=True)
        config.write_text(vendor_config.replace(str(source / "vendor"), "../vendor"))
        shutil.copytree(notices, source / "PROTONPASS-NOTICES")
        (source / "BUILD-PROTONPASS.txt").write_text(
            "Install Rust >=1.96 with the wasm32-wasip1 target, then:\n"
            "  cd rosec-protonpass\n"
            "  cargo build --offline --locked --release --target wasm32-wasip1 --lib\n"
            "Do not enable test-http for distribution.\n"
            "Rust toolchain and platform system libraries are build prerequisites.\n"
        )
        with tarfile.open(output / f"rosec-provider-protonpass-{args.version}.source.tar.gz", "w:gz") as tar:
            tar.add(source, arcname=f"rosec-protonpass-source-{args.version}")
    print(f"Packaged {len(inventory)} dependency notices and corresponding source at {output}")


if __name__ == "__main__":
    main()
