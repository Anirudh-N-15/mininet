#!/usr/bin/env bash
# Step 5: mitigation, live. Each run = one scenario with one policy.
#   ./egl/run_step5.sh [kernel|user] ["scenario:policy ..."]
# policy = none | <detector>-bypass | <detector>-meter
#   none              detect only, never act (the "no defence" baseline)
#   ewma_egl-bypass   EWMA+gate acts; verified clients skip the SYN meter
#   ewma_egl-meter    EWMA+gate acts; plain SYN meter for everyone (ablation)
#   static-bypass     the Static detector acts (shows false-alarm collateral)
# Default: the comparison set for the paper (about 60 minutes).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DATAPATH=${1:-kernel}
RUNS=${2:-"abrupt:none abrupt:ewma_egl-bypass abrupt:ewma_egl-meter \
crowd:none crowd:static-meter crowd:static-bypass crowd:ewma_egl-bypass \
ramp:none ramp:ewma_egl-bypass ramp:ewma_egl-meter"}
export EGL_DETECTORS=static,ewma,hst,ewma_egl,hst_egl
export EGL_VERIFY_CLIENTS=1

for RUN in $RUNS; do
  SC=${RUN%%:*}; POLICY=${RUN#*:}
  if [ "$POLICY" = none ]; then
    export EGL_MITIGATE_ON=none EGL_BYPASS=1
  else
    export EGL_MITIGATE_ON=${POLICY%-*}
    [ "${POLICY##*-}" = bypass ] && export EGL_BYPASS=1 || export EGL_BYPASS=0
  fi
  TAG="step5_${SC}_${POLICY}"
  export EGL_TELEMETRY_CSV="$ROOT/results/${TAG}_telemetry.csv"
  export EGL_DETECTOR_CSV="$ROOT/results/${TAG}_detectors.csv"
  export EGL_MITIGATION_CSV="$ROOT/results/${TAG}_mitigation.csv"
  echo "=== $SC with policy $POLICY ==="
  start_ryu "results/ryu_${TAG}.log" egl.egl_controller egl.detector_app egl.mitigator_app
  as_root /usr/bin/python3 -m egl.check_step5 --scenario "$SC" --datapath "$DATAPATH" \
    || echo "!! $RUN: sanity check failed"
  stop_ryu
done
plot egl.plot_step5
