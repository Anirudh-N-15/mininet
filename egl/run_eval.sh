#!/usr/bin/env bash
# Step 5b: the full evaluation for the paper (about 3.8 hours with defaults).
#
#   ./egl/run_eval.sh [kernel|user] [stages]
#   stages (default all): detection growth completing mitigation margin early distributed
#
# RESUMABLE: a run whose result JSON already exists is skipped, so if the
# laptop sleeps or something crashes, run the same command again.
# Progress: results/eval/progress.log (one line per run, with timestamps).
# At the end the analysis runs: python3 -m egl.analyze_eval
#
#   REPEATS_DETECTION=5  repeats for the detection stage
#   REPEATS=3            repeats for the other stages
#   QUICK=1              1 repeat and fast ramps (5 %/s): a smoke test, ~25 min
#
# Stages
#   detection   5 detectors side by side; abrupt, crowd, ramp +0.5 %/s
#   growth      ramp at +1 %/s and +2 %/s
#   completing  bots with real addresses doing full HTTP requests (limitation)
#   mitigation  none / plain meter / bypass on abrupt, crowd (Static acts), ramp +1 %/s
#   margin      bypass with meter margin 0.5, 1.0, 2.5 on the abrupt flood
#   early       attack starts INSIDE the warm-up: first-version gate vs fixed gate
#   distributed validation subset with the attack split over h1, h11 and h12
#
# Since 26 Nov every attack is split over h1, h11 and h12 by default (a real
# DDoS). Results from before that used h1 alone; each result file records
# its attack hosts.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DATAPATH=${1:-kernel}
STAGES=${2:-"detection growth completing mitigation margin early distributed"}
QUICK=${QUICK:-0}
if [ "$QUICK" = 1 ]; then
  REPEATS_DETECTION=1; REPEATS=1; G_DET=0.05; G_MIT=0.05; MARGINS="1.0"; GROWTHS="0.05"
else
  REPEATS_DETECTION=${REPEATS_DETECTION:-5}; REPEATS=${REPEATS:-3}
  G_DET=0.005; G_MIT=0.01; MARGINS="0.5 1.0 2.5"; GROWTHS="0.01 0.02"
fi
EVAL="$ROOT/results/eval"
mkdir -p "$EVAL"
PROGRESS="$EVAL/progress.log"
log() { echo "$(date '+%F %T')  $*" | tee -a "$PROGRESS"; }

# one detection run: <stage> <name> <scenario> [extra check_step3 args]
det_run() {
  local stage=$1 name=$2 sc=$3; shift 3
  local dir="$EVAL/$stage"; mkdir -p "$dir"
  if [ -f "$dir/${name}_${sc}.json" ]; then log "skip  $stage/$name $sc (done)"; return; fi
  export EGL_DETECTORS=${DET_SET:-static,ewma,hst,ewma_egl,hst_egl} EGL_VERIFY_CLIENTS=0
  export EGL_TELEMETRY_CSV="$dir/${name}_${sc}_telemetry.csv"
  export EGL_DETECTOR_CSV="$dir/${name}_${sc}_detectors.csv"
  log "start $stage/$name $sc $*"
  start_ryu "$dir/ryu_${name}_${sc}.log" egl.egl_controller egl.detector_app
  as_root /usr/bin/python3 -m egl.check_step3 --prefix "$name" --scenario "$sc" \
    --datapath "$DATAPATH" --detector-csv "$EGL_DETECTOR_CSV" "$@" \
    >"$dir/${name}_${sc}.out" 2>&1 || log "  !! sanity check failed (see $dir/${name}_${sc}.out)"
  stop_ryu
  log "done  $stage/$name $sc"
}

# one mitigation run: <stage> <scenario> <policy> <suffix> <margin> <growth> [attackers]
mit_run() {
  local stage=$1 sc=$2 policy=$3 suffix=$4 margin=$5 growth=$6 attackers=${7:-h1,h11,h12}
  local dir="$EVAL/$stage"; mkdir -p "$dir"
  export EGL_METER_MARGIN=$margin
  if [ "$policy" = none ]; then export EGL_MITIGATE_ON=none EGL_BYPASS=1
  else
    export EGL_MITIGATE_ON=${policy%-*}
    [ "${policy##*-}" = bypass ] && export EGL_BYPASS=1 || export EGL_BYPASS=0
  fi
  local label=$policy
  [ "$policy" != none ] && [ "$margin" != 1.5 ] && label="${policy}-m${margin}"
  local tag="step5_${sc}_${label}${suffix}"
  if [ -f "$dir/$tag.json" ]; then log "skip  $stage/$tag (done)"; return; fi
  export EGL_DETECTORS=static,ewma,hst,ewma_egl,hst_egl EGL_VERIFY_CLIENTS=1
  export EGL_TELEMETRY_CSV="$dir/${tag}_telemetry.csv"
  export EGL_DETECTOR_CSV="$dir/${tag}_detectors.csv"
  export EGL_MITIGATION_CSV="$dir/${tag}_mitigation.csv"
  log "start $stage/$tag"
  start_ryu "$dir/ryu_${tag}.log" egl.egl_controller egl.detector_app egl.mitigator_app
  as_root /usr/bin/python3 -m egl.check_step5 --scenario "$sc" --datapath "$DATAPATH" \
    --results "$dir" --suffix "$suffix" --growth "$growth" --attackers "$attackers" \
    >"$dir/$tag.out" 2>&1 || log "  !! sanity check failed (see $dir/$tag.out)"
  stop_ryu
  log "done  $stage/$tag"
}

log "=== run_eval: datapath=$DATAPATH stages='$STAGES' quick=$QUICK ==="
for STAGE in $STAGES; do
  case $STAGE in
    detection)
      for r in $(seq 1 "$REPEATS_DETECTION"); do
        for sc in abrupt crowd ramp; do det_run detection "r$r" "$sc" --growth "$G_DET"; done
      done ;;
    growth)
      for g in $GROWTHS; do
        for r in $(seq 1 "$REPEATS"); do det_run growth "g${g}_r$r" ramp --growth "$g"; done
      done ;;
    completing)
      for r in $(seq 1 "$REPEATS"); do
        det_run completing "r$r" ramp --growth 0.02 --attacker completing
      done ;;
    mitigation)
      for r in $(seq 1 "$REPEATS"); do
        for p in none ewma_egl-meter ewma_egl-bypass; do mit_run mitigation abrupt "$p" "_r$r" 1.5 "$G_MIT"; done
        for p in none static-meter static-bypass; do mit_run mitigation crowd "$p" "_r$r" 1.5 "$G_MIT"; done
        for p in none ewma_egl-meter ewma_egl-bypass; do mit_run mitigation ramp "$p" "_r$r" 1.5 "$G_MIT"; done
      done ;;
    margin)
      for m in $MARGINS; do
        for r in $(seq 1 2); do mit_run margin abrupt ewma_egl-bypass "_r$r" "$m" "$G_MIT"; done
      done ;;
    early)
      for r in $(seq 1 "$REPEATS"); do
        DET_SET=static,ewma,hst,ewma_egl,hst_egl,ewma_egl_legacy,hst_egl_legacy \
          det_run early "r$r" early --early-at 10
      done ;;
    distributed)
      for r in $(seq 1 2); do
        det_run distributed "r$r" abrupt --attackers h1,h11,h12
        det_run distributed "r$r" ramp --growth "$G_MIT" --attackers h1,h11,h12
        for p in none ewma_egl-bypass; do
          mit_run distributed abrupt "$p" "_r$r" 1.5 "$G_MIT" h1,h11,h12
        done
      done
      det_run distributed "c1" ramp --growth 0.02 --attacker completing --attackers h1,h11,h12 ;;
    *) log "unknown stage $STAGE" ;;
  esac
done
log "=== all runs finished; analysing ==="
plot egl.analyze_eval --eval "$EVAL"
log "=== done: see results/eval/report/ ==="
