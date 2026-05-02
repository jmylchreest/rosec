# Internal notes

Maintainer-facing documents that don't belong on the public docs site at <https://jmylchreest.github.io/rosec>:

- **[design-offline-cache.md](./design-offline-cache.md)** — design rationale for the encrypted offline-cache export/restore protocol used by WASM providers that declare the `OfflineCache` capability. Reference for anyone changing the cache wire format or eviction policy.
- **[tech-debt.md](./tech-debt.md)** — running list of refactor / cleanup items that aren't blockers for any release.

The contributor-facing **WASM provider guide** lives on the public docs site under [Developers → WASM Provider Guide](https://jmylchreest.github.io/rosec/developers/wasm-provider-guide). Anyone writing a third-party plugin should be reading that, not internal notes.
