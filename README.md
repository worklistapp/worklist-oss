# Worklist OSS

Open-source Rust workspace for the `worklist` CLI and shared client crates.

This repository contains the early public client surface for Worklist:

- `worklist`: command-line client for authenticating, reading decrypted work lists/tasks/comments, and creating or updating tasks and comments
- `worklist-client-core`: shared public types and error handling
- `worklist-client-auth`: local credential storage and authentication helpers
- `worklist-client-api`: typed HTTP client for the Worklist API
- `worklist-client-crypto`: client-side crypto helpers for sealed payloads and key derivation
- `worklist-client-runtime`: unlock-aware runtime that projects raw API responses into agent-facing decrypted models

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
crates/client-runtime/  # decrypted agent-facing runtime and read models
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
cargo run -p worklist -- auth unlock --password-stdin
cargo run -p worklist -- auth keychain store --password-stdin
cargo run -p worklist -- --json tasks get --work-list-id <list-id> --task-id <task-id>
cargo run -p worklist -- --json tasks attachments read --work-list-id <list-id> --task-id <task-id> --attachment-id <attachment-id>
cargo run -p worklist -- --json tasks attachments download --work-list-id <list-id> --task-id <task-id> --attachment-id <attachment-id>
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

- The CLI defaults to table/text output for humans; pass `--json` for machine-readable output.
- Read commands return decrypted agent-facing models by default; raw wire DTOs are only available through hidden debug flags.
- Agent `/me/tasks`, `tasks assigned`, and all-work-list task listings are assignment-gated: work-list grants authorize access, but a task appears in these views only after an explicit assignee delegation to that agent. Upgrades from grant-wide task listing behavior should assign or backfill agent delegations intentionally.
- Encrypted read and write commands are non-interactive by default. Use `auth unlock --password-stdin` for a temporary in-memory session, or `auth keychain store --password-stdin` to persist a local bootstrap secret in the platform keychain.
- `tasks get` includes typed attachment metadata and lists attachment IDs in table output.
- `tasks attachments read` prints readable attachments to stdout, including plain text passthrough and DOCX rendered as Markdown; with `--json` it emits the rendered content plus attachment metadata.
- `tasks attachments download` decrypts binary attachments and saves them locally; if `--output` is omitted it writes `./<attachment-file-name>`.
- The current workspace targets encrypted Worklist flows, so authenticated reads and writes still depend on credentials, local key unwrap, and workspace keys from a live Worklist deployment.
- CI for this repository runs from `.github/workflows/ci.yml`.
- Crates.io release steps are documented in [`RELEASE.md`](./RELEASE.md), with a helper script at [`scripts/publish-crates.sh`](./scripts/publish-crates.sh).

## Repository Flow

This public repository is mirrored automatically from Worklist's upstream development repository. The code here is intended to be consumable as a normal standalone Rust workspace, but some changes may land here after first being developed upstream.

## License

This workspace is licensed under `GPL-3.0-only`. See [LICENSE](./LICENSE).
