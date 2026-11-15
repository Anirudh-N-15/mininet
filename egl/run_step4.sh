#!/usr/bin/env bash
# Step 4: the Learning Gate, live, about 13 minutes.
#   ./egl/run_step4.sh [kernel|user] [scenarios]     scenarios default: "abrupt crowd ramp"
# Plain and gated detectors run side by side on the same windows.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DATAPATH=${1:-kernel}
SCENARIOS=${2:-abrupt crowd ramp}
export EGL_DETECTORS=${EGL_DETECTORS:-static,ewma,hst,ewma_egl,hst_egl}
export EGL_TAU=${EGL_TAU:-0.7}

for SC in $SCENARIOS; do
  export EGL_TELEMETRY_CSV="$ROOT/results/step4_${SC}_telemetry.csv"
  export EGL_DETECTOR_CSV="$ROOT/results/step4_${SC}_detectors.csv"
  echo "=== $SC ==="
  start_ryu "results/ryu_step4_${SC}.log" egl.egl_controller egl.detector_app
  as_root /usr/bin/python3 -m egl.check_step3 --prefix step4 --scenario "$SC" \
    --datapath "$DATAPATH" --detector-csv "$EGL_DETECTOR_CSV" || echo "!! $SC: sanity check failed"
  stop_ryu
done
plot egl.plot_step3 --prefix step4
