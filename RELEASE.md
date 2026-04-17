# Releasing Worklist OSS Crates

This workspace publishes to crates.io in dependency order:

1. `worklist-client-core`
2. `worklist-client-auth`
3. `worklist-client-crypto`
4. `worklist-client-api`
5. `worklist`

Downstream crates depend on earlier crates being visible on crates.io, so releasing them back-to-back without waiting will fail.

## Requirements

- a crates.io account with publish access
- `cargo login` already configured locally, or `CARGO_REGISTRY_TOKEN` set in the environment
- a clean git worktree unless you explicitly opt into `ALLOW_DIRTY=1`

## Dry Run

From the repository root:

```bash
DRY_RUN=1 ./scripts/publish-crates.sh
```

Dry-run mode fully runs `cargo publish --dry-run` for `worklist-client-core`, then packages downstream crates with `cargo package --no-verify --list`. That avoids crates.io index failures before the earlier internal crates are published.

## Publish

```bash
./scripts/publish-crates.sh
```

The script publishes each crate, then polls crates.io for the exact version before continuing to the next one.

## Useful Overrides

```bash
ALLOW_DIRTY=1 ./scripts/publish-crates.sh
WAIT_SECONDS=15 MAX_ATTEMPTS=40 ./scripts/publish-crates.sh
```

- `ALLOW_DIRTY=1`: allow packaging and publishing from a dirty worktree
- `WAIT_SECONDS`: seconds between crates.io visibility checks
- `MAX_ATTEMPTS`: maximum visibility checks before the script exits with an error

## Manual Recovery

If a publish succeeds but the script exits before the next crate, rerun it after the published version appears on crates.io. `cargo publish` will refuse to republish the same version, so you can continue safely after visibility catches up.
