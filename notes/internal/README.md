# Internal notes

Contributor- and maintainer-facing documents that don't belong on the public docs site at <https://jmylchreest.github.io/rosec>:

- **[design-offline-cache.md](./design-offline-cache.md)** — design rationale for the encrypted offline-cache export/restore protocol used by WASM providers that declare the `OfflineCache` capability.
- **[tech-debt.md](./tech-debt.md)** — running list of refactor / cleanup items that aren't blockers for any release.
- **[wasm-provider-guide.md](./wasm-provider-guide.md)** — guide for authors writing new WASM provider plugins. Covers the guest function contract, host imports (`host_file`, `host_http`, `host_watch`), readiness probes, error handling, and the offline cache protocol.

These live outside `docs/` so they don't get bundled into the user-facing Docusaurus build or AUR docs packages.
