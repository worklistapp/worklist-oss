# StrongBox WASM Build

The StrongBox WASM bridge source lives in `oss/crates/strong-box-wasm` and builds from the public OSS workspace.

The workspace currently includes `oss/crates/strong-box` because the first spike against the published `strong-box = 0.5.1` crate failed for `wasm32-unknown-unknown`: that published dependency graph pulls `getrandom 0.3` without a supported backend for this target. Keep the fork public until the needed WASM target support is released upstream.

```bash
cd oss
cargo build -p strong-box-wasm --profile wasm-release --target wasm32-unknown-unknown
```

The package script `bun run build:wasm` rebuilds the artifact and copies it to `src/crypto/wasm/strong_box_wasm_bg.wasm`. The script `bun run verify:wasm` rebuilds the artifact and compares SHA256 hashes against the checked-in browser artifact.
