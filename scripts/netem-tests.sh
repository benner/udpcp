#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
# SPDX-License-Identifier: MIT

# Container integration tests for udpcp — sender and receiver in separate containers.
# Applies tc netem inside the receiver container (NET_ADMIN) for adverse conditions.
# Does not require root; requires podman or docker and a working container runtime.
# Requires: rustup target add x86_64-unknown-linux-musl
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="docker.io/library/alpine:latest"
MUSL_TARGET="x86_64-unknown-linux-musl"
PASS=0
FAIL=0
ERRORS=()

die() {
    echo "FATAL: $*" >&2
    exit 1
}

if [ -z "${CONTAINER_RUNTIME:-}" ]; then
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        CONTAINER_RUNTIME=podman
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        CONTAINER_RUNTIME=docker
    else
        die "no functional container runtime found (podman or docker)"
    fi
fi

check_prereqs() {
    command -v cargo >/dev/null 2>&1 || die "cargo not found in PATH"
    rustup target list --installed 2>/dev/null | grep -q "^${MUSL_TARGET}" ||
        die "Rust musl target not installed — run: rustup target add ${MUSL_TARGET}"
}

ensure_image() {
    if ! "$CONTAINER_RUNTIME" image exists "$IMAGE" 2>/dev/null; then
        echo "Pulling $IMAGE ..."
        "$CONTAINER_RUNTIME" pull "$IMAGE"
    fi
}

build_static_binary() {
    local bin="$1"
    cargo build --release --target "$MUSL_TARGET" \
        --manifest-path "$REPO_ROOT/Cargo.toml" --quiet ||
        die "cargo build failed"
    cp "$REPO_ROOT/target/$MUSL_TARGET/release/udpcp" "$bin"
}

cleanup_network() {
    local net="$1"
    "$CONTAINER_RUNTIME" network rm -f "$net" >/dev/null 2>&1 || true
}

cleanup_container() {
    local name="$1"
    "$CONTAINER_RUNTIME" stop -t 0 "$name" >/dev/null 2>&1 || true
    "$CONTAINER_RUNTIME" rm -f "$name" >/dev/null 2>&1 || true
}

run_test() {
    local name="$1" bin="$2" size="$3" delay_ms="$4" loss_pct="$5"
    local net recv_name tmpdir src_file out_dir recv_ip

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN

    net="udpcp_net_$$_${name}"
    recv_name="udpcp_recv_$$_${name}"
    src_file="$tmpdir/src.bin"
    out_dir="$tmpdir/out"
    mkdir -p "$out_dir"

    printf "  %-30s " "$name"

    if [[ "$size" -gt 0 ]]; then
        head -c "$size" /dev/urandom >"$src_file"
    else
        touch "$src_file"
    fi

    "$CONTAINER_RUNTIME" network create "$net" >/dev/null
    trap 'cleanup_network "$net"; rm -rf "$tmpdir"' RETURN

    local recv_cmd
    if [[ "$delay_ms" -gt 0 || "$loss_pct" != "0" ]]; then
        local netem="tc qdisc add dev eth0 root netem"
        [[ "$delay_ms" -gt 0 ]] && netem+=" delay ${delay_ms}ms"
        [[ "$loss_pct" != "0" ]] && netem+=" loss ${loss_pct}%"
        recv_cmd="apk add -q --no-cache iproute2 >/dev/null 2>&1 && $netem && exec /udpcp recv 9999 /out/dst.bin"
        set -- sh -c "$recv_cmd"
    else
        set -- /udpcp recv 9999 /out/dst.bin
    fi

    "$CONTAINER_RUNTIME" run --rm \
        --name "$recv_name" \
        --net "$net" \
        --cap-add NET_ADMIN \
        -v "${bin}:/udpcp:ro" \
        -v "${out_dir}:/out" \
        "$IMAGE" "$@" >"$tmpdir/recv.log" 2>&1 &
    local recv_pid=$!
    trap 'cleanup_container "$recv_name"; wait "$recv_pid" 2>/dev/null || true; cleanup_network "$net"; rm -rf "$tmpdir"' RETURN

    recv_ip=""
    for _ in $(seq 30); do
        recv_ip="$("$CONTAINER_RUNTIME" inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$recv_name" 2>/dev/null || true)"
        [[ -n "$recv_ip" ]] && break
        sleep 0.2
    done
    if [[ -z "$recv_ip" ]]; then
        echo "FAIL (receiver IP not available)"
        echo "--- receiver log ---"
        cat "$tmpdir/recv.log"
        FAIL=$((FAIL + 1))
        ERRORS+=("$name")
        return
    fi

    if ! "$CONTAINER_RUNTIME" run --rm \
        --net "$net" \
        -v "${bin}:/udpcp:ro" \
        -v "${src_file}:/src.bin:ro" \
        "$IMAGE" \
        /udpcp send /src.bin "${recv_ip}:9999" \
        >"$tmpdir/send.log" 2>&1; then
        echo "FAIL (sender error)"
        echo "--- sender log ---"
        cat "$tmpdir/send.log"
        echo "--- receiver log ---"
        cat "$tmpdir/recv.log"
        FAIL=$((FAIL + 1))
        ERRORS+=("$name")
        return
    fi

    # Sender received FIN — receiver has already flushed and hash-verified the file;
    # kill the container rather than waiting out the linger timeout.
    cleanup_container "$recv_name"
    wait "$recv_pid" 2>/dev/null || true

    if ! cmp -s "$src_file" "$out_dir/dst.bin"; then
        echo "FAIL (content mismatch)"
        FAIL=$((FAIL + 1))
        ERRORS+=("$name")
        return
    fi

    echo "ok"
    PASS=$((PASS + 1))
}

check_prereqs
ensure_image

TMPDIR_BIN="$(mktemp -d)"
TMPBIN="$TMPDIR_BIN/udpcp"
trap 'rm -rf "$TMPDIR_BIN"' EXIT
echo "Building static Rust binary (${MUSL_TARGET}) ..."
build_static_binary "$TMPBIN"

CHUNK=1400

echo ""
echo "Running container tests (runtime: $CONTAINER_RUNTIME):"
echo ""

# NAME                       BIN       BYTES               DELAY_MS  LOSS_PCT
run_test basic "$TMPBIN" $((20 * CHUNK)) 0 0
run_test delay_20ms "$TMPBIN" $((20 * CHUNK)) 20 0
run_test delay_100ms "$TMPBIN" $((10 * CHUNK)) 100 0
run_test loss_5pct "$TMPBIN" $((20 * CHUNK)) 0 5
run_test loss_15pct "$TMPBIN" $((20 * CHUNK)) 0 15
run_test delay_20ms_loss10 "$TMPBIN" $((20 * CHUNK)) 20 10

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ "${#ERRORS[@]}" -gt 0 ]]; then
    echo "Failed tests: ${ERRORS[*]}"
    exit 1
fi
