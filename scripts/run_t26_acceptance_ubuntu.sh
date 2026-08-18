#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly ARTIFACT_ROOT="$PROJECT_ROOT/run_log/t2.6"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

(($# == 0)) || die "usage: bash scripts/run_t26_acceptance_ubuntu.sh"
((EUID != 0)) || die "run as the normal Ubuntu user"

for command in cmake ctest c++ ldd ninja pkg-config python3 shellcheck tee; do
    command -v "$command" >/dev/null || die "missing required command: $command"
done

shellcheck --severity=error "$0"
[[ -f "$HOME/.local/nids-toolchain/env.sh" ]] || die "missing locked toolchain environment"
# shellcheck disable=SC1091
source "$HOME/.local/nids-toolchain/env.sh"

[[ ! -e "$ARTIFACT_ROOT/acceptance.json" ]] \
    || die "refusing to overwrite existing T2.6 acceptance"
mkdir -p -- "$ARTIFACT_ROOT"

python3 -B "$PROJECT_ROOT/scripts/verify_t26_core_acceptance.py" check \
    --source "$PROJECT_ROOT" \
    2>&1 | tee "$ARTIFACT_ROOT/source-contract.log"
python3 -B "$PROJECT_ROOT/scripts/verify_t26_core_acceptance.py" run \
    --source "$PROJECT_ROOT" \
    --artifact-root "$ARTIFACT_ROOT" \
    2>&1 | tee "$ARTIFACT_ROOT/acceptance-run.log"
python3 -B "$PROJECT_ROOT/scripts/verify_t26_core_acceptance.py" validate \
    --input "$ARTIFACT_ROOT/acceptance.json" \
    2>&1 | tee -a "$ARTIFACT_ROOT/acceptance-run.log"
