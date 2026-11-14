#!/usr/bin/env bash
# Step 2: abrupt flood vs frog-boiling ramp, about 4.5 minutes.
#   ./egl/run_step2.sh [kernel|user] [growth]      e.g. ./egl/run_step2.sh kernel 0.02
# A fresh Ryu (and a fresh telemetry CSV) for each mode, so runs never mix.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DATAPATH=${1:-kernel}
GROWTH=${2:-0.02}

for MODE in abrupt ramp; do
  export EGL_TELEMETRY_CSV="$ROOT/results/step2_${MODE}_telemetry.csv"
  echo "=== $MODE ==="
  start_ryu "results/ryu_step2_${MODE}.log"
  as_root /usr/bin/python3 -m egl.check_step2 --mode "$MODE" --datapath "$DATAPATH" \
    --growth "$GROWTH" --csv "$EGL_TELEMETRY_CSV" || echo "!! $MODE run failed"
  stop_ryu
done
echo; echo "Summaries: results/step2_abrupt.json  results/step2_ramp.json"
plot egl.plot_step2
