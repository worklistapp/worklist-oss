# OSS Workspace

This repository contains the draft public workspace for the future Worklist agent CLI and shared client crates.

It is designed to work in two contexts:

1. as the root of the public `worklistapp/worklist-oss` repository,
2. as the `oss/` subtree inside the private Worklist monorepo,
3. as the release surface for public crates and binaries once the API and license surface are settled.

## Goals

- isolate the future public client from private backend code,
- keep crate boundaries explicit,
- make `git subtree split --prefix oss` viable,
- avoid coupling the public CLI to the root workspace.

## Layout

In the private monorepo, this workspace lives under `oss/`. In the public mirror, these entries live at the repository root.

```text
cli/                    # public CLI binary
crates/client-core/     # shared errors, config, public types
crates/client-auth/     # OPAQUE/session/unlock flows
crates/client-api/      # typed API client
crates/client-crypto/   # client-side crypto and payload builders
.github/workflows/ci.yml
```

## Current Status

This is a scaffold, not the extracted implementation yet.

- crate names and boundaries are intentional,
- source files are placeholders,
- all crates are marked `publish = false`,
- the workspace is standalone and is not included in the private monorepo root workspace.

## Mirroring

This workspace is intended to be mirrored automatically from the private Worklist monorepo into `worklistapp/worklist-oss`.

- The private monorepo is the source of truth.
- Maintainers run the subtree split and push automation from that upstream repository.
- The public mirror receives the resulting `oss/` history on its `main` branch.

If you are reading this file inside the private monorepo, the mirroring automation lives outside this subtree, at the repository root.

## Commands

Public mirror:

```bash
cargo check
cargo test
cargo run -p worklist-cli-oss -- --help
```

Private monorepo root:

```bash
cargo check --manifest-path oss/Cargo.toml
cargo test --manifest-path oss/Cargo.toml
cargo run --manifest-path oss/Cargo.toml -p worklist-cli-oss -- --help
```

## Licensing

The workspace currently inherits `GPL-3.0-only` because the existing crypto stack in this repository already uses that license. Revisit this before publication if the crypto dependency story changes.
