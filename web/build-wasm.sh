#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${CLIENT_ROOT}/sshcast-proto/Cargo.toml" ]; then
    PROTO_MANIFEST="${CLIENT_ROOT}/sshcast-proto/Cargo.toml"
    TARGET_DIR="${CLIENT_ROOT}/sshcast-proto/target"
else
    PROTO_MANIFEST="${CLIENT_ROOT}/../sshcast-proto/Cargo.toml"
    TARGET_DIR="${CLIENT_ROOT}/../sshcast-proto/target"
fi

if command -v rustup >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown || true
fi

echo "==> Building sshcast_proto.wasm (wasm32-unknown-unknown)..."
cargo build --manifest-path "${PROTO_MANIFEST}" --target wasm32-unknown-unknown --release

WASM_OUT="${TARGET_DIR}/wasm32-unknown-unknown/release/sshcast_proto.wasm"
cp "${WASM_OUT}" "${SCRIPT_DIR}/sshcast_proto.wasm"
echo "==> Wrote ${SCRIPT_DIR}/sshcast_proto.wasm ($(du -h "${SCRIPT_DIR}/sshcast_proto.wasm" | cut -f1))"

if [ -d "${CLIENT_ROOT}/../sshcast-server/internal/web/assets" ]; then
    cp "${WASM_OUT}" "${CLIENT_ROOT}/../sshcast-server/internal/web/assets/sshcast_proto.wasm"
    echo "==> Also copied sshcast_proto.wasm to sshcast-server/internal/web/assets/"
fi
