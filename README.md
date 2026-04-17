# Worklist OSS

Open-source Rust workspace for the `worklist` CLI and shared client crates.

This repository contains the early public client surface for Worklist:

- `worklist`: command-line client for authenticating, listing work lists, inspecting encrypted payloads, and creating or updating tasks and comments
- `worklist-client-core`: shared public types and error handling
- `worklist-client-auth`: local credential storage and authentication helpers
- `worklist-client-api`: typed HTTP client for the Worklist API
- `worklist-client-crypto`: client-side crypto helpers for sealed payloads and key derivation

## Status

This workspace is still in active development and is not yet positioned as a stable public SDK.

- crate boundaries are intentional, but APIs may still change
- several APIs may still evolve as the agent workflow surface expands
- the current release target is the CLI first, with supporting crates published alongside it

## Layout

```text
cli/                    # public CLI binary
crates/client-core/     # shared public types and errors
crates/client-auth/     # auth, credentials, and session helpers
crates/client-api/      # typed API client
crates/client-crypto/   # client-side crypto and payload helpers
.github/workflows/ci.yml
```

## Getting Started

Requirements:

- Rust stable toolchain

Common commands:

```bash
cargo check
cargo test
cargo run -p worklist -- --help
```

Once the crate is published, install the CLI with:

```bash
cargo install worklist
```

Set a custom API URL with `WORKLIST_API_URL` if you are not targeting the default hosted endpoint:

```bash
WORKLIST_API_URL=https://your-worklist.example cargo run -p worklist -- me
```

## Development Notes

- The CLI defaults to JSON output for data-oriented commands.
- The current workspace targets encrypted Worklist flows, so some commands expect credentials, sealed payloads, and workspace keys from a live Worklist deployment.
- CI for this repository runs from `.github/workflows/ci.yml`.
- Crates.io release steps are documented in [`RELEASE.md`](./RELEASE.md), with a helper script at [`scripts/publish-crates.sh`](./scripts/publish-crates.sh).

## Repository Flow

This public repository is mirrored automatically from Worklist's upstream development repository. The code here is intended to be consumable as a normal standalone Rust workspace, but some changes may land here after first being developed upstream.

## License

This workspace is licensed under `GPL-3.0-only`. See [LICENSE](./LICENSE).
