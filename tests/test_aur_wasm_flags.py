"""Build a real WASM guest with hostile inherited makepkg flags (no downloads)."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RECIPE = Path(__file__).resolve().parents[1] / "contrib/aur/PKGBUILD-git"


class AurWasmFlagsTests(unittest.TestCase):
    def test_host_flags_are_isolated_and_native_environment_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname="flag-probe"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\ncrate-type=["cdylib"]\n'
            )
            (root / "src/lib.rs").write_text(
                '#[unsafe(no_mangle)] pub extern "C" fn answer() -> u32 { 42 }\n'
            )
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True)
            env = dict(os.environ, RUSTFLAGS="-C target-cpu=native",
                       CARGO_ENCODED_RUSTFLAGS="-C\x1ftarget-cpu=native")
            for name in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS"):
                env[name] = "-march=native"
            script = r"""
set -eu
source "$1"
before=$(env | sort)
cargo() {
    for flag in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CFLAGS CXXFLAGS CPPFLAGS LDFLAGS; do
        [[ -z "${!flag}" ]] || return 99
    done
    command cargo "$@"
}
_build_wasm
[[ "$before" == "$(env | sort)" ]]
"""
            result = subprocess.run(["bash", "-c", script, "test", str(RECIPE)],
                                    cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("not a recognized", result.stderr)
            wasm = root / "target/wasm32-wasip1/release/flag_probe.wasm"
            self.assertEqual(wasm.read_bytes()[:4], b"\0asm")


if __name__ == "__main__":
    unittest.main()
