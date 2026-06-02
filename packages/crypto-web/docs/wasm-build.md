# StrongBox WASM Build

The StrongBox WASM bridge source lives in `oss/crates/strong-box-wasm` and builds from the public OSS workspace.

The workspace currently includes `oss/crates/strong-box` because the first spike against the published `strong-box = 0.5.1` crate failed for `wasm32-unknown-unknown`: that published dependency graph pulls `getrandom 0.3` without a supported backend for this target. Keep the fork public until the needed WASM target support is released upstream.

```bash
cd oss
../scripts/build-strong-box-wasm.sh
```

The package script `bun run build:wasm` rebuilds the artifact with deterministic `CARGO_ENCODED_RUSTFLAGS` path remapping and copies it to `src/crypto/wasm/strong_box_wasm_bg.wasm`. The root `scripts/build-strong-box-wasm.sh` script applies the same remapping. The script `bun run verify:wasm` rebuilds the artifact and compares SHA256 hashes against the checked-in browser artifact.

Exact byte-for-byte verification is enforced on Linux x64, matching the pinned Docker builder and GitHub Actions runner used by the OSS CI. Other hosts still rebuild the bridge and reject missing or implausibly small artifacts, but they may report a host-specific hash instead of failing the command.
