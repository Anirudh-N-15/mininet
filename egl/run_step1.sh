#!/usr/bin/env bash
# Step 1 in one command: start Ryu with the EGL controller, run the acceptance
# test in Mininet, stop everything.        ./egl/run_step1.sh [kernel|user]
#
# "kernel" (default) = normal OVS kernel datapath (your Ubuntu VM).
# "user"             = OVS userspace datapath (machines without the OVS module).
set -euo pipefail
DATAPATH=${1:-kernel}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RYU_ENV=${RYU_ENV:-$HOME/ryu-env}
cd "$ROOT"
mkdir -p results
export EVENTLET_NO_GREENDNS=yes
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export EGL_TELEMETRY_CSV="$ROOT/results/egl_telemetry.csv"
LOG="$ROOT/results/ryu_step1.log"

cleanup() { kill "${RYU_PID:-}" 2>/dev/null || true; sudo mn -c >/dev/null 2>&1 || true; }
trap cleanup EXIT
sudo mn -c >/dev/null 2>&1 || true

"$RYU_ENV/bin/ryu-manager" --ofp-tcp-listen-port 6653 egl/egl_controller.py >"$LOG" 2>&1 &
RYU_PID=$!
for _ in $(seq 1 40); do
  (echo >/dev/tcp/127.0.0.1/6653) 2>/dev/null && break
  kill -0 "$RYU_PID" 2>/dev/null || { echo "Ryu died:"; tail -20 "$LOG"; exit 1; }
  sleep 0.5
done

sudo -E env "PATH=$PATH" /usr/bin/python3 -m egl.check_step1 \
  --datapath "$DATAPATH" --csv "$EGL_TELEMETRY_CSV"
echo; grep -E "confirmed|ERROR" "$LOG" || true
