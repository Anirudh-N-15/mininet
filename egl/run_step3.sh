#!/usr/bin/env bash
# Step 3: Static / EWMA / Half-Space Trees live in Ryu, about 13 minutes.
#   ./egl/run_step3.sh [kernel|user] [scenarios]     scenarios default: "abrupt crowd ramp"
#   e.g. ./egl/run_step3.sh kernel crowd              (just the flash crowd, ~3 min)
# A fresh Ryu per scenario: detectors learn their baseline once.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DATAPATH=${1:-kernel}
SCENARIOS=${2:-abrupt crowd ramp}

for SC in $SCENARIOS; do
  export EGL_TELEMETRY_CSV="$ROOT/results/step3_${SC}_telemetry.csv"
  export EGL_DETECTOR_CSV="$ROOT/results/step3_${SC}_detectors.csv"
  echo "=== $SC ==="
  start_ryu "results/ryu_step3_${SC}.log" egl.egl_controller egl.detector_app
  as_root /usr/bin/python3 -m egl.check_step3 --scenario "$SC" --datapath "$DATAPATH" \
    --detector-csv "$EGL_DETECTOR_CSV" || echo "!! $SC: sanity check failed"
  stop_ryu
done
plot egl.plot_step3
