#!/usr/bin/env bash
# Step 1: Ryu + counter telemetry test, about 50 s.     ./egl/run_step1.sh [kernel|user]
#   kernel (default) = normal OVS; user = OVS userspace datapath (no OVS kernel module)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DATAPATH=${1:-kernel}
export EGL_TELEMETRY_CSV="$ROOT/results/egl_telemetry.csv"

start_ryu results/ryu_step1.log
as_root /usr/bin/python3 -m egl.check_step1 --datapath "$DATAPATH" --csv "$EGL_TELEMETRY_CSV"
echo; grep -E "confirmed|ERROR" results/ryu_step1.log || true
