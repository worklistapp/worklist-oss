#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DRY_RUN="${DRY_RUN:-0}"
ALLOW_DIRTY="${ALLOW_DIRTY:-0}"
WAIT_SECONDS="${WAIT_SECONDS:-10}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"

CRATES=(
  "worklist-client-core"
  "worklist-client-auth"
  "worklist-client-crypto"
  "worklist-client-api"
  "worklist"
)

cargo_publish_args=(publish --manifest-path Cargo.toml)
if [[ "${ALLOW_DIRTY}" == "1" ]]; then
  cargo_publish_args+=(--allow-dirty)
fi

cargo_package_args=(package --manifest-path Cargo.toml --no-verify --list)
if [[ "${ALLOW_DIRTY}" == "1" ]]; then
  cargo_package_args+=(--allow-dirty)
fi

crate_version() {
  local crate="$1"
  local pkgid

  pkgid="$(cargo pkgid --manifest-path Cargo.toml -p "${crate}")"
  printf '%s\n' "${pkgid##*@}"
}

wait_for_crate_version() {
  local crate="$1"
  local version="$2"
  local url="https://crates.io/api/v1/crates/${crate}/${version}"
  local attempt=1

  while (( attempt <= MAX_ATTEMPTS )); do
    if curl --silent --show-error --fail "${url}" >/dev/null; then
      printf 'Confirmed %s %s on crates.io.\n' "${crate}" "${version}"
      return 0
    fi

    printf 'Waiting for %s %s to appear on crates.io (%d/%d)...\n' \
      "${crate}" "${version}" "${attempt}" "${MAX_ATTEMPTS}"
    sleep "${WAIT_SECONDS}"
    ((attempt += 1))
  done

  printf 'Timed out waiting for %s %s to appear on crates.io.\n' "${crate}" "${version}" >&2
  return 1
}

for crate in "${CRATES[@]}"; do
  version="$(crate_version "${crate}")"

  if [[ "${DRY_RUN}" == "1" ]]; then
    if [[ "${crate}" == "worklist-client-core" ]]; then
      printf '\n==> Dry-run publishing %s %s\n' "${crate}" "${version}"
      cargo "${cargo_publish_args[@]}" --dry-run -p "${crate}"
    else
      printf '\n==> Packaging %s %s for dry-run validation\n' "${crate}" "${version}"
      cargo "${cargo_package_args[@]}" -p "${crate}"
    fi
    continue
  fi

  printf '\n==> Publishing %s %s\n' "${crate}" "${version}"
  cargo "${cargo_publish_args[@]}" -p "${crate}"
  wait_for_crate_version "${crate}" "${version}"
done

if [[ "${DRY_RUN}" == "1" ]]; then
  printf '\nDry run completed successfully.\n'
else
  printf '\nAll crates published successfully.\n'
fi
