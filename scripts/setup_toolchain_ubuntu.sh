#!/usr/bin/env bash
# Install and verify the reproducible T0.2 userspace toolchain on Ubuntu 24.04.
# This script never configures NICs, hugepages, IOMMU, VFIO, or boot settings.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly LOCK_FILE="${NIDS_TOOLCHAIN_LOCK:-$PROJECT_ROOT/config/toolchain.lock.json}"
readonly TOOLCHAIN_ROOT="${NIDS_TOOLCHAIN_ROOT:-$HOME/.local/nids-toolchain}"
readonly CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/nids-toolchain"
readonly WORK_ROOT="$CACHE_ROOT/work"
readonly DOWNLOAD_ROOT="$CACHE_ROOT/downloads"

MODE=""
ROLLBACK_PATH=""
RECEIPT_PATH="$PROJECT_ROOT/toolchain-receipt.json"
FORCE_RECEIPT=0
JOBS="${NIDS_BUILD_JOBS:-}"
CLEANUP_DIRS=()
PARTIAL_FILES=()
SMOKE_BINARY=""
DPDK_PARENT=""
DPDK_STAGING_PREFIX=""
DPDK_OPERATION_LOCK=""

usage() {
    cat <<'EOF'
Usage:
  bash scripts/setup_toolchain_ubuntu.sh --dry-run
  bash scripts/setup_toolchain_ubuntu.sh --install
  bash scripts/setup_toolchain_ubuntu.sh --verify [--receipt PATH] [--force-receipt]
  bash scripts/setup_toolchain_ubuntu.sh --upgrade-dpdk-apps
  bash scripts/setup_toolchain_ubuntu.sh --rollback-dpdk BACKUP_PATH

Environment overrides:
  NIDS_TOOLCHAIN_ROOT  Install root (default: ~/.local/nids-toolchain)
  NIDS_BUILD_JOBS      Parallel build jobs (default from lock, capped by caller)
  NIDS_TOOLCHAIN_LOCK  Alternate lock file for controlled testing
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[T0.2] %s\n' "$*"
}

cleanup() {
    local directory partial
    for directory in "${CLEANUP_DIRS[@]:-}"; do
        if [[ -n "$directory" && "$directory" == "$WORK_ROOT/"* && -d "$directory" ]]; then
            rm -rf -- "$directory"
        fi
    done
    for partial in "${PARTIAL_FILES[@]:-}"; do
        if [[ -n "$partial" && "$partial" == "$DOWNLOAD_ROOT/"*.part.* && -f "$partial" ]]; then
            rm -f -- "$partial"
        fi
    done
    if [[ -n "${DPDK_STAGING_PREFIX:-}" \
        && -n "${DPDK_PARENT:-}" \
        && "$DPDK_STAGING_PREFIX" == "$DPDK_PARENT/.nids-dpdk-staging-"* \
        && -d "$DPDK_STAGING_PREFIX" \
        && ! -L "$DPDK_STAGING_PREFIX" ]]; then
        rm -rf -- "$DPDK_STAGING_PREFIX"
    fi
    if [[ -n "${DPDK_OPERATION_LOCK:-}" \
        && -n "${DPDK_PARENT:-}" \
        && "$DPDK_OPERATION_LOCK" == "$DPDK_PARENT/.nids-dpdk-operation.lock" \
        && -d "$DPDK_OPERATION_LOCK" \
        && ! -L "$DPDK_OPERATION_LOCK" ]]; then
        rmdir -- "$DPDK_OPERATION_LOCK"
    fi
}
trap cleanup EXIT

json_value() {
    local path="$1"
    python3 - "$LOCK_FILE" "$path" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
value = document
for component in sys.argv[2].split("."):
    value = value[component]
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

json_array() {
    local path="$1"
    python3 - "$LOCK_FILE" "$path" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
value = document
for component in sys.argv[2].split("."):
    value = value[component]
if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
    raise SystemExit(f"{sys.argv[2]} must be an array of strings")
print("\n".join(value))
PY
}

while (($#)); do
    case "$1" in
        --dry-run|--install|--verify|--upgrade-dpdk-apps)
            [[ -z "$MODE" ]] || die "choose exactly one mode"
            MODE="$1"
            ;;
        --rollback-dpdk)
            [[ -z "$MODE" ]] || die "choose exactly one mode"
            MODE="$1"
            shift
            (($#)) || die "--rollback-dpdk requires a backup path"
            ROLLBACK_PATH="$1"
            ;;
        --receipt)
            shift
            (($#)) || die "--receipt requires a path"
            RECEIPT_PATH="$1"
            ;;
        --force-receipt)
            FORCE_RECEIPT=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
    shift
done
[[ -n "$MODE" ]] || { usage >&2; exit 2; }
[[ -f "$LOCK_FILE" ]] || die "lock file not found: $LOCK_FILE"

readonly DPDK_VERSION="$(json_value dpdk.version)"
readonly DPDK_URL="$(json_value dpdk.url)"
readonly DPDK_ARCHIVE="$(json_value dpdk.archive_name)"
readonly DPDK_ARCHIVE_ROOT="$(json_value dpdk.archive_root)"
readonly DPDK_SHA256="$(json_value dpdk.sha256)"
readonly DPDK_MD5="$(json_value dpdk.official_md5)"
readonly DPDK_PREFIX="$TOOLCHAIN_ROOT/$(json_value dpdk.install_subdir)"
readonly DPDK_BUILD_OPTIONS_SHA256="$(json_value dpdk.build_options_sha256)"
readonly ORT_VERSION="$(json_value onnxruntime.version)"
readonly ORT_URL="$(json_value onnxruntime.url)"
readonly ORT_ARCHIVE="$(json_value onnxruntime.archive_name)"
readonly ORT_SHA256="$(json_value onnxruntime.sha256)"
readonly ORT_PREFIX="$TOOLCHAIN_ROOT/$(json_value onnxruntime.install_subdir)"
readonly ENV_FILE="$TOOLCHAIN_ROOT/env.sh"
DPDK_PARENT="$(dirname -- "$DPDK_PREFIX")"
readonly DPDK_PARENT
mapfile -t APT_PACKAGES < <(json_array apt_packages)
mapfile -t DPDK_MESON_OPTIONS < <(json_array dpdk.meson_options)
mapfile -t DPDK_REQUIRED_EXECUTABLES < <(json_array dpdk.required_executables)
if [[ -z "$JOBS" ]]; then
    JOBS="$(json_value installation.default_jobs)"
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "NIDS_BUILD_JOBS must be a positive integer"

validate_install_root() {
    local normalized_root normalized_home path
    [[ "$TOOLCHAIN_ROOT" == /* ]] || die "NIDS_TOOLCHAIN_ROOT must be an absolute path"
    normalized_root="$(realpath -m -- "$TOOLCHAIN_ROOT")"
    normalized_home="$(realpath -m -- "$HOME")"
    [[ "$TOOLCHAIN_ROOT" == "$normalized_root" ]] || die "NIDS_TOOLCHAIN_ROOT must be normalized: $normalized_root"
    case "$TOOLCHAIN_ROOT" in
        ""|/|/usr|/usr/local|"$HOME")
            die "unsafe NIDS_TOOLCHAIN_ROOT: $TOOLCHAIN_ROOT"
            ;;
    esac
    [[ "$TOOLCHAIN_ROOT" == "$normalized_home/"* ]] || die "NIDS_TOOLCHAIN_ROOT must remain under HOME"
    for path in "$TOOLCHAIN_ROOT" "$DPDK_PARENT" "$DPDK_PREFIX"; do
        [[ ! -L "$path" ]] || die "refusing symlinked toolchain path: $path"
    done
}

validate_lock_contract() {
    local calculated
    calculated="$(python3 - "$LOCK_FILE" <<'PY'
import hashlib
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
options = document["dpdk"]["meson_options"]
encoded = json.dumps(options, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(encoded).hexdigest())
PY
)"
    [[ "$calculated" == "$DPDK_BUILD_OPTIONS_SHA256" ]] || die "DPDK build-options fingerprint does not match lock"
    [[ "${DPDK_REQUIRED_EXECUTABLES[*]}" == "dpdk-testpmd dpdk-dumpcap" ]] \
        || die "DPDK required executable contract is invalid"
}

check_target() {
    local require_build_resources="${1:-1}"
    [[ ${EUID:-$(id -u)} -ne 0 ]] || die "run as a normal user; the script invokes sudo only for APT"
    [[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"
    # shellcheck disable=SC1091
    source /etc/os-release
    local expected_id expected_version expected_arch current_arch memory_bytes free_bytes
    expected_id="$(json_value target.os_id)"
    expected_version="$(json_value target.os_version_prefix)"
    expected_arch="$(json_value target.architecture)"
    [[ "${ID:-}" == "$expected_id" ]] || die "expected $expected_id, found ${ID:-unknown}"
    [[ "${VERSION_ID:-}" == "$expected_version"* ]] || die "expected Ubuntu $expected_version.x, found ${VERSION_ID:-unknown}"
    current_arch="$(uname -m)"
    [[ "$current_arch" == "$expected_arch" ]] || die "expected $expected_arch, found $current_arch"

    if ((require_build_resources)); then
        memory_bytes="$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) * 1024 ))"
        free_bytes="$(df -PB1 "$HOME" | awk 'NR == 2 {print $4}')"
        ((memory_bytes >= $(json_value target.minimum_memory_bytes))) || die "less than 2 GiB RAM available to the VM"
        ((free_bytes >= $(json_value target.minimum_free_disk_bytes))) || die "less than 8 GiB free under HOME"
    fi
}

show_plan() {
    printf '%s\n' \
        "Target root: $TOOLCHAIN_ROOT" \
        "Cache root: $CACHE_ROOT" \
        "Build jobs: $JOBS" \
        "DPDK: $DPDK_VERSION" \
        "  URL: $DPDK_URL" \
        "  SHA-256: $DPDK_SHA256" \
        "  Build options SHA-256: $DPDK_BUILD_OPTIONS_SHA256" \
        "  Required executables: ${DPDK_REQUIRED_EXECUTABLES[*]}" \
        "ONNX Runtime: $ORT_VERSION" \
        "  URL: $ORT_URL" \
        "  SHA-256: $ORT_SHA256" \
        "APT packages: ${APT_PACKAGES[*]}" \
        "No NIC, hugepage, IOMMU, VFIO, or boot configuration will be changed."
}

verify_archive() {
    local path="$1" expected_sha256="$2" expected_md5="${3:-}"
    printf '%s  %s\n' "$expected_sha256" "$path" | sha256sum --check --status - || return 1
    if [[ -n "$expected_md5" ]]; then
        printf '%s  %s\n' "$expected_md5" "$path" | md5sum --check --status - || return 1
    fi
}

download_archive() {
    local url="$1" name="$2" sha256="$3" md5="${4:-}" destination partial
    destination="$DOWNLOAD_ROOT/$name"
    mkdir -p -- "$DOWNLOAD_ROOT"
    if [[ -f "$destination" ]]; then
        verify_archive "$destination" "$sha256" "$md5" || die "cached archive checksum mismatch: $destination"
        log "reusing verified archive $destination"
        printf '%s\n' "$destination"
        return
    fi
    partial="$destination.part.$$"
    PARTIAL_FILES+=("$partial")
    curl --proto '=https' --tlsv1.2 --fail --location --retry 3 --output "$partial" "$url"
    verify_archive "$partial" "$sha256" "$md5" || die "download checksum mismatch: $url"
    mv -- "$partial" "$destination"
    log "downloaded and verified $name"
    printf '%s\n' "$destination"
}

write_marker() {
    local prefix="$1" component="$2" version="$3" sha256="$4" build_options_sha256="${5:-}"
    python3 - "$prefix/.nids-artifact.json" "$component" "$version" "$sha256" "$build_options_sha256" <<'PY'
import datetime as dt
import json
import os
import sys

path, component, version, sha256, build_options_sha256 = sys.argv[1:]
document = {
    "schema_version": "1.0.0",
    "component": component,
    "version": version,
    "source_sha256": sha256,
    "installed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
}
if build_options_sha256:
    document["build_options_sha256"] = build_options_sha256
with open(path, "w", encoding="utf-8", newline="\n") as output:
    json.dump(document, output, indent=2)
    output.write("\n")
os.chmod(path, 0o644)
PY
}

install_apt_dependencies() {
    log "refreshing Ubuntu APT metadata"
    sudo apt-get update
    log "installing build dependencies"
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "${APT_PACKAGES[@]}"
}

dpdk_marker_matches() {
    local prefix="$1"
    python3 - "$prefix/.nids-artifact.json" "$DPDK_VERSION" "$DPDK_SHA256" "$DPDK_BUILD_OPTIONS_SHA256" <<'PY'
import json
import sys

path, version, source_sha256, build_options_sha256 = sys.argv[1:]
try:
    document = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
expected = {
    "component": "dpdk",
    "version": version,
    "source_sha256": source_sha256,
    "build_options_sha256": build_options_sha256,
}
raise SystemExit(0 if all(document.get(key) == value for key, value in expected.items()) else 1)
PY
}

dpdk_marker_matches_source() {
    local prefix="$1"
    python3 - "$prefix/.nids-artifact.json" "$DPDK_VERSION" "$DPDK_SHA256" <<'PY'
import json
import sys

path, version, source_sha256 = sys.argv[1:]
try:
    document = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
expected = {"component": "dpdk", "version": version, "source_sha256": source_sha256}
raise SystemExit(0 if all(document.get(key) == value for key, value in expected.items()) else 1)
PY
}

verify_dpdk_prefix() {
    local prefix="$1" detected executable linkage
    [[ -d "$prefix" && ! -L "$prefix" ]] || return 1
    [[ -f "$prefix/lib/pkgconfig/libdpdk.pc" ]] || return 1
    dpdk_marker_matches "$prefix" || return 1
    detected="$(PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --modversion libdpdk 2>/dev/null)" || return 1
    [[ "$detected" == "$DPDK_VERSION" ]] || return 1
    for executable in "${DPDK_REQUIRED_EXECUTABLES[@]}"; do
        [[ -x "$prefix/bin/$executable" && ! -L "$prefix/bin/$executable" ]] || return 1
        linkage="$(LD_LIBRARY_PATH="$prefix/lib" ldd "$prefix/bin/$executable" 2>&1)" || return 1
        [[ "$linkage" != *"not found"* ]] || return 1
    done
}

dpdk_prefix_is_known_source() {
    local prefix="$1" detected
    [[ -d "$prefix" && ! -L "$prefix" ]] || return 1
    [[ -x "$prefix/bin/dpdk-testpmd" && ! -L "$prefix/bin/dpdk-testpmd" ]] || return 1
    [[ -f "$prefix/lib/pkgconfig/libdpdk.pc" ]] || return 1
    dpdk_marker_matches_source "$prefix" || return 1
    detected="$(PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --modversion libdpdk 2>/dev/null)" || return 1
    [[ "$detected" == "$DPDK_VERSION" ]]
}

acquire_dpdk_operation_lock() {
    local lock="$DPDK_PARENT/.nids-dpdk-operation.lock"
    [[ -d "$DPDK_PARENT" && ! -L "$DPDK_PARENT" ]] || die "DPDK parent is not a safe directory: $DPDK_PARENT"
    mkdir -- "$lock" 2>/dev/null || die "another DPDK install, upgrade, or rollback may be active: $lock"
    DPDK_OPERATION_LOCK="$lock"
}

require_upgrade_tools() {
    local command
    for command in curl ldd md5sum meson ninja pkg-config python3 sha256sum tar; do
        command -v "$command" >/dev/null || die "required upgrade command not found: $command"
    done
}

build_dpdk_staging() {
    local archive work source build destdir installed staging
    archive="$(download_archive "$DPDK_URL" "$DPDK_ARCHIVE" "$DPDK_SHA256" "$DPDK_MD5" | tail -n 1)"
    mkdir -p -- "$WORK_ROOT" "$DPDK_PARENT"
    work="$(mktemp -d "$WORK_ROOT/dpdk.XXXXXX")"
    CLEANUP_DIRS+=("$work")
    tar -xf "$archive" -C "$work"
    source="$work/$DPDK_ARCHIVE_ROOT"
    build="$work/build"
    destdir="$work/destdir"
    staging="$DPDK_PARENT/.nids-dpdk-staging-$DPDK_VERSION-$$"
    [[ ! -e "$staging" ]] || die "DPDK staging collision: $staging"
    [[ -f "$source/meson.build" ]] || die "unexpected DPDK archive layout"
    meson setup "$build" "$source" --prefix "$DPDK_PREFIX" "${DPDK_MESON_OPTIONS[@]}"
    ninja -C "$build" -j "$JOBS"
    DESTDIR="$destdir" meson install -C "$build"
    installed="$destdir$DPDK_PREFIX"
    [[ -d "$installed" ]] || die "DPDK staged install is missing: $installed"
    mv -T -- "$installed" "$staging"
    DPDK_STAGING_PREFIX="$staging"
    write_marker "$staging" dpdk "$DPDK_VERSION" "$DPDK_SHA256" "$DPDK_BUILD_OPTIONS_SHA256"
    verify_dpdk_prefix "$staging" || die "staged DPDK failed pkg-config or dynamic-linkage verification"
}

atomic_exchange() {
    local left="$1" right="$2"
    python3 - "$left" "$right" <<'PY'
import ctypes
import os
import sys

left, right = map(os.fsencode, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
if renameat2(-100, left, -100, right, 2) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
PY
}

install_dpdk() {
    mkdir -p -- "$DPDK_PARENT"
    acquire_dpdk_operation_lock
    if [[ -e "$DPDK_PREFIX" ]]; then
        if verify_dpdk_prefix "$DPDK_PREFIX"; then
            log "DPDK $DPDK_VERSION with locked apps is already installed"
            return
        fi
        die "existing DPDK prefix is not valid for this lock; run --upgrade-dpdk-apps explicitly: $DPDK_PREFIX"
    fi
    build_dpdk_staging
    mv -T -- "$DPDK_STAGING_PREFIX" "$DPDK_PREFIX"
    DPDK_STAGING_PREFIX=""
    verify_dpdk_prefix "$DPDK_PREFIX" || die "installed DPDK failed final verification"
    log "installed DPDK $DPDK_VERSION under $DPDK_PREFIX"
}

upgrade_dpdk_apps() {
    local backup staging
    acquire_dpdk_operation_lock
    [[ -e "$DPDK_PREFIX" ]] || die "DPDK prefix does not exist; use --install: $DPDK_PREFIX"
    if verify_dpdk_prefix "$DPDK_PREFIX"; then
        die "DPDK prefix already matches the locked app set; upgrade refused"
    fi
    dpdk_prefix_is_known_source "$DPDK_PREFIX" \
        || die "existing DPDK prefix is incomplete, untrusted, or a different version; upgrade refused"
    backup="$DPDK_PARENT/.nids-dpdk-backup-$DPDK_VERSION-$(date -u +%Y%m%dT%H%M%SZ)"
    [[ ! -e "$backup" ]] || die "DPDK backup collision: $backup"
    build_dpdk_staging
    staging="$DPDK_STAGING_PREFIX"
    atomic_exchange "$DPDK_PREFIX" "$staging" || die "atomic DPDK prefix exchange failed before activation"
    DPDK_STAGING_PREFIX=""
    if ! mv -T -- "$staging" "$backup"; then
        if atomic_exchange "$DPDK_PREFIX" "$staging"; then
            DPDK_STAGING_PREFIX="$staging"
            die "backup placement failed; original DPDK prefix was restored"
        fi
        die "backup placement and automatic rollback both failed; inspect $DPDK_PREFIX and $staging"
    fi
    if ! verify_dpdk_prefix "$DPDK_PREFIX"; then
        atomic_exchange "$DPDK_PREFIX" "$backup" \
            || die "post-exchange verification and automatic rollback both failed"
        die "post-exchange verification failed; original DPDK prefix was restored"
    fi
    log "upgraded DPDK apps transactionally; previous prefix retained at $backup"
    log "rollback command: bash scripts/setup_toolchain_ubuntu.sh --rollback-dpdk $backup"
}

rollback_dpdk() {
    local backup="$1" normalized backup_name version_pattern
    [[ "$backup" == /* ]] || die "rollback backup path must be absolute"
    normalized="$(realpath -m -- "$backup")"
    [[ "$backup" == "$normalized" ]] || die "rollback backup path must be normalized: $normalized"
    [[ "$(dirname -- "$backup")" == "$DPDK_PARENT" ]] || die "rollback backup must be a direct child of $DPDK_PARENT"
    backup_name="$(basename -- "$backup")"
    version_pattern="${DPDK_VERSION//./\.}"
    [[ "$backup_name" =~ ^\.nids-dpdk-backup-${version_pattern}-[0-9]{8}T[0-9]{6}Z$ ]] \
        || die "rollback backup name is not recognized"
    acquire_dpdk_operation_lock
    [[ -d "$backup" && ! -L "$backup" ]] || die "rollback backup is not a safe directory: $backup"
    [[ -d "$DPDK_PREFIX" && ! -L "$DPDK_PREFIX" ]] || die "active DPDK prefix is not a safe directory"
    dpdk_prefix_is_known_source "$backup" || die "rollback backup marker or DPDK version is not trusted"
    dpdk_prefix_is_known_source "$DPDK_PREFIX" || die "active DPDK marker or version is not trusted"
    atomic_exchange "$DPDK_PREFIX" "$backup" || die "atomic DPDK rollback exchange failed"
    log "exchanged active DPDK prefix with backup; no directory was deleted"
    log "repeat the same command to reverse this rollback: --rollback-dpdk $backup"
}

install_onnxruntime() {
    local archive work detected
    if [[ -f "$ORT_PREFIX/include/onnxruntime_cxx_api.h" && -f "$ORT_PREFIX/lib/libonnxruntime.so" ]]; then
        detected="$(PKG_CONFIG_PATH="$ORT_PREFIX/lib/pkgconfig" pkg-config --modversion onnxruntime 2>/dev/null || true)"
        if [[ "$detected" == "$ORT_VERSION" ]]; then
            log "ONNX Runtime $ORT_VERSION is already installed"
            return
        fi
    fi
    [[ ! -e "$ORT_PREFIX" ]] || die "incomplete or mismatched ONNX Runtime prefix exists: $ORT_PREFIX"
    archive="$(download_archive "$ORT_URL" "$ORT_ARCHIVE" "$ORT_SHA256" | tail -n 1)"
    mkdir -p -- "$WORK_ROOT" "$(dirname -- "$ORT_PREFIX")"
    work="$(mktemp -d "$WORK_ROOT/onnxruntime.XXXXXX")"
    CLEANUP_DIRS+=("$work")
    tar -xzf "$archive" -C "$work" --strip-components=1
    [[ -f "$work/include/onnxruntime_cxx_api.h" && -f "$work/lib/libonnxruntime.so" ]] || die "unexpected ONNX Runtime archive layout"
    mkdir -p -- "$work/lib/pkgconfig"
    {
        printf 'prefix=%s\n' "$ORT_PREFIX"
        printf 'libdir=${prefix}/lib\n'
        printf 'includedir=${prefix}/include\n\n'
        printf 'Name: onnxruntime\n'
        printf 'Description: ONNX Runtime CPU C/C++ release archive\n'
        printf 'Version: %s\n' "$ORT_VERSION"
        printf 'Libs: -L${libdir} -lonnxruntime\n'
        printf 'Cflags: -I${includedir}\n'
    } >"$work/lib/pkgconfig/onnxruntime.pc"
    write_marker "$work" onnxruntime "$ORT_VERSION" "$ORT_SHA256"
    mv -- "$work" "$ORT_PREFIX"
    detected="$(PKG_CONFIG_PATH="$ORT_PREFIX/lib/pkgconfig" pkg-config --modversion onnxruntime)"
    [[ "$detected" == "$ORT_VERSION" ]] || die "installed ONNX Runtime version mismatch: $detected"
    log "installed ONNX Runtime $detected under $ORT_PREFIX"
}

write_environment() {
    mkdir -p -- "$TOOLCHAIN_ROOT"
    python3 - "$ENV_FILE" "$TOOLCHAIN_ROOT" "$DPDK_PREFIX" "$ORT_PREFIX" <<'PY'
import os
import shlex
import sys

path, root, dpdk, ort = sys.argv[1:]
values = {"NIDS_TOOLCHAIN_ROOT": root, "DPDK_ROOT": dpdk, "ONNXRUNTIME_ROOT": ort}
lines = ["# Generated by T0.2; source this file from Bash."]
for name, value in values.items():
    lines.append(f"export {name}={shlex.quote(value)}")
lines.extend(
    [
        'export PATH="$DPDK_ROOT/bin:$PATH"',
        'export PKG_CONFIG_PATH="$DPDK_ROOT/lib/pkgconfig:$ONNXRUNTIME_ROOT/lib/pkgconfig:${PKG_CONFIG_PATH:-}"',
        'export LD_LIBRARY_PATH="$DPDK_ROOT/lib:$ONNXRUNTIME_ROOT/lib:${LD_LIBRARY_PATH:-}"',
        'export CMAKE_PREFIX_PATH="$DPDK_ROOT:$ONNXRUNTIME_ROOT:${CMAKE_PREFIX_PATH:-}"',
    ]
)
with open(path, "w", encoding="utf-8", newline="\n") as output:
    output.write("\n".join(lines) + "\n")
os.chmod(path, 0o644)
PY
    log "wrote environment file $ENV_FILE"
}

run_clean_smoke_build() {
    local work
    mkdir -p -- "$WORK_ROOT"
    work="$(mktemp -d "$WORK_ROOT/smoke.XXXXXX")"
    CLEANUP_DIRS+=("$work")
    cmake -S "$PROJECT_ROOT/tests/toolchain_smoke" -B "$work" -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build "$work" --parallel "$JOBS"
    ctest --test-dir "$work" --output-on-failure
    SMOKE_BINARY="$work/nids_toolchain_smoke"
    [[ -x "$SMOKE_BINARY" ]] || die "smoke binary was not produced"
}

verify_toolchain() {
    [[ -f "$ENV_FILE" ]] || die "environment file not found; run --install first"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    bash -n "$PROJECT_ROOT/scripts/setup_toolchain_ubuntu.sh"
    shellcheck --severity=error "$PROJECT_ROOT/scripts/setup_toolchain_ubuntu.sh"
    run_clean_smoke_build
    local force_arguments=()
    if ((FORCE_RECEIPT)); then
        force_arguments+=(--force)
    fi
    python3 "$PROJECT_ROOT/scripts/verify_toolchain.py" collect \
        --lock "$LOCK_FILE" \
        --smoke-binary "$SMOKE_BINARY" \
        --output "$RECEIPT_PATH" \
        "${force_arguments[@]}"
    log "verification receipt: $RECEIPT_PATH"
}

validate_install_root
validate_lock_contract
case "$MODE" in
    --dry-run)
        show_plan
        ;;
    --install)
        check_target
        install_apt_dependencies
        install_dpdk
        install_onnxruntime
        write_environment
        log "installation complete; run --verify next"
        ;;
    --verify)
        check_target
        verify_toolchain
        ;;
    --upgrade-dpdk-apps)
        check_target
        require_upgrade_tools
        upgrade_dpdk_apps
        ;;
    --rollback-dpdk)
        check_target 0
        rollback_dpdk "$ROLLBACK_PATH"
        ;;
esac
