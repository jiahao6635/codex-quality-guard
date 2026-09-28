#!/usr/bin/env bash
set -euo pipefail

: "${CPR_BIN:?Set CPR_BIN to the deployed codex-proxy-rs executable}"
: "${CPR_WORKDIR:?Set CPR_WORKDIR to the deployed gateway working directory}"
: "${QUALITY_GUARD_INSTANCE_ID:?Set QUALITY_GUARD_INSTANCE_ID to the installed plugin instance UUID}"
: "${QUALITY_GUARD_LOCK_FILE:?Set QUALITY_GUARD_LOCK_FILE to a writable lock path}"

# 锁覆盖整个宿主 CLI 生命周期；跳过重叠 tick，不排队堆积探针。
exec 9>"$QUALITY_GUARD_LOCK_FILE"
if ! flock --nonblock 9; then
  exit 0
fi
cd "$CPR_WORKDIR"
exec "$CPR_BIN" plugin "$QUALITY_GUARD_INSTANCE_ID" tick
