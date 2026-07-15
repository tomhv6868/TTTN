#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly REQUIREMENTS="$PROJECT_ROOT/config/t32-scapy-requirements.txt"
readonly TOOLCHAIN_ROOT="$HOME/.local/nids-toolchain"
readonly VENV_PARENT="$TOOLCHAIN_ROOT/venvs"
readonly VENV_ROOT="$VENV_PARENT/t3.2"
readonly LOCKED_SCAPY_VERSION="2.7.0"

STAGING_ROOT=""

usage() {
    cat <<'EOF'
Usage:
  bash scripts/setup_t32_scapy_ubuntu.sh --install
  bash scripts/setup_t32_scapy_ubuntu.sh --verify
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[T3.2 Scapy] %s\n' "$*"
}

cleanup() {
    if [[ -n "$STAGING_ROOT" \
        && "$STAGING_ROOT" == "$VENV_PARENT/.t3.2-staging."* \
        && -d "$STAGING_ROOT" \
        && ! -L "$STAGING_ROOT" ]]; then
        rm -rf -- "$STAGING_ROOT"
    fi
}
trap cleanup EXIT

check_host() {
    [[ ${EUID:-$(id -u)} -ne 0 ]] || die "run as the normal Ubuntu user"
    [[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || die "expected Ubuntu, found ${ID:-unknown}"
    [[ "${VERSION_ID:-}" == "24.04"* ]] \
        || die "expected Ubuntu 24.04.x, found ${VERSION_ID:-unknown}"
    [[ "$(uname -m)" == "x86_64" ]] || die "expected x86_64"
    command -v python3 >/dev/null || die "python3 is required"
    [[ "$(python3 -c 'import platform; print(platform.python_version())')" == 3.12.* ]] \
        || die "Python 3.12.x is required"
}

check_paths() {
    local normalized_home normalized_toolchain normalized_venv
    normalized_home="$(realpath -m -- "$HOME")"
    normalized_toolchain="$(realpath -m -- "$TOOLCHAIN_ROOT")"
    normalized_venv="$(realpath -m -- "$VENV_ROOT")"
    [[ "$normalized_toolchain" == "$normalized_home/.local/nids-toolchain" ]] \
        || die "unexpected toolchain root: $normalized_toolchain"
    [[ "$normalized_venv" == "$normalized_toolchain/venvs/t3.2" ]] \
        || die "unexpected T3.2 venv root: $normalized_venv"
    for path in "$TOOLCHAIN_ROOT" "$VENV_PARENT" "$VENV_ROOT"; do
        [[ ! -L "$path" ]] || die "refusing symlinked install path: $path"
    done
    [[ -f "$REQUIREMENTS" ]] || die "requirements lock is missing: $REQUIREMENTS"
}

verify_environment() {
    local root="$1"
    local python="$root/bin/python"
    [[ -x "$python" ]] || die "venv Python is missing: $python"
    "$python" - "$root" "$LOCKED_SCAPY_VERSION" <<'PY'
import importlib.metadata
import pathlib
import sys

from scapy.utils import RawPcapNgReader

expected_root = pathlib.Path(sys.argv[1]).resolve()
expected_version = sys.argv[2]
actual_root = pathlib.Path(sys.prefix).resolve()
actual_version = importlib.metadata.version("scapy")
if actual_root != expected_root:
    raise SystemExit(f"venv prefix mismatch: {actual_root} != {expected_root}")
if actual_version != expected_version:
    raise SystemExit(f"Scapy version mismatch: {actual_version} != {expected_version}")
if RawPcapNgReader.__module__ != "scapy.utils":
    raise SystemExit("Scapy RawPcapNgReader identity mismatch")
print(f"Scapy {actual_version}; Python {sys.version.split()[0]}; prefix {actual_root}")
PY
    "$python" -m pip check
}

install_environment() {
    if [[ -e "$VENV_ROOT" ]]; then
        verify_environment "$VENV_ROOT"
        log "existing locked environment is valid"
        return
    fi
    mkdir -p -- "$VENV_PARENT"
    STAGING_ROOT="$(mktemp -d "$VENV_PARENT/.t3.2-staging.XXXXXX")"
    python3 -m venv "$STAGING_ROOT"
    PIP_CONFIG_FILE=/dev/null PIP_NO_INPUT=1 \
        "$STAGING_ROOT/bin/python" -m pip install \
        --disable-pip-version-check \
        --index-url https://pypi.org/simple \
        --no-deps \
        --only-binary=:all: \
        --require-hashes \
        --requirement "$REQUIREMENTS"
    verify_environment "$STAGING_ROOT"
    [[ ! -e "$VENV_ROOT" ]] || die "T3.2 venv appeared during installation"
    mv -- "$STAGING_ROOT" "$VENV_ROOT"
    STAGING_ROOT=""
    verify_environment "$VENV_ROOT"
    log "installed locked environment at $VENV_ROOT"
}

(($# == 1)) || { usage >&2; exit 2; }
check_host
check_paths
case "$1" in
    --install)
        install_environment
        ;;
    --verify)
        verify_environment "$VENV_ROOT"
        ;;
    -h|--help)
        usage
        ;;
    *)
        die "unknown argument: $1"
        ;;
esac

log "acceptance command: $VENV_ROOT/bin/python -B $PROJECT_ROOT/scripts/verify_t32_golden_dataset.py run"
