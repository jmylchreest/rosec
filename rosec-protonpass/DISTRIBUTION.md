# Distribution and licence record

The Proton Pass WASM provider is **GPL-3.0-or-later**, including local adaptations.
The original MIT licence on rosec's own host source remains intact. Preserve
both sets of notices when distributing them together; WASM is not itself a
legal exemption from copyleft. The plugin is built and packaged separately and
does not link the Bitwarden SDK or any proprietary Proton runtime.

The production WASI normal/build dependency closure was inspected on
2026-10-10. Its licence expressions are MIT, Apache-2.0, BSD-3-Clause, or
compatible alternatives; unicode-ident additionally requires Unicode-3.0.
Apache-2.0 code can be incorporated into a GPLv3 work ([Apache guidance](https://www.apache.org/licenses/GPL-compatibility)).
Keep the individual dependency notices: licensing the resulting plugin under
GPL does not remove their attribution requirements. The packaging script rejects
new, unreviewed licence expressions and missing licence texts.
The three Extism 1.41.0 workspace crates that omit their licence files use the
checked-in upstream text under `notices/extism-1.41.0`, pinned by revision and hash.

Each release must provide, together in the same download location:

- `rosec-provider-protonpass-VERSION.wasm.tar.gz`: production WASM, network policy,
  combined signature, GPL text, provenance and dependency notices.
- `rosec-provider-protonpass-VERSION.source.tar.gz`: exact committed source,
  lockfiles, build scripts and vendored dependencies, with offline build instructions.
- Checksums covering both archives. The source commit is recorded in the notices.

This follows the corresponding-source delivery approach in GPLv3 section 6(d),
rather than relying on a written offer or an upstream URL remaining available.
See the [GPLv3 text](https://www.gnu.org/licenses/gpl-3.0.html) and
[FSF plugin guidance](https://www.gnu.org/licenses/gpl-faq.en.html#GPLPlugins).
The Rust compiler/WASI standard library and system build tools are prerequisites;
they are not embedded as source in the archive.

Generate materials from a clean committed checkout:

```sh
python3 contrib/package-protonpass.py --version VERSION --output dist/protonpass
```

The release workflow signs the production WASM/policy with the existing release
key and verifies the signature against the host's embedded public keys. It never
enables `test-http`. The AUR binary package installs the same signed files and
licence notices. Registering/pushing the AUR package and publishing a release
remain deployment steps; preparing these files does not perform either action.

Do not represent the MIT host licence as covering the GPL guest. Distributors
combining this package with additional modules must check those modules' terms;
this record covers this plugin's dependency closure, not arbitrary combinations.
