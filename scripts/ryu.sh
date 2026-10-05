#!/usr/bin/env bash

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RYU_ENV="${RYU_ENV:-/home/anirudh/ryu-env}"

cd "$REPO_ROOT"
source "$RYU_ENV/bin/activate"
export EVENTLET_NO_GREENDNS=yes
export PYTHONPATH="$REPO_ROOT/custom:$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"
export DDOS_MONITOR_OUTPUT="${DDOS_MONITOR_OUTPUT:-$REPO_ROOT/ddos_metrics.csv}"
export DDOS_BASELINE_SECONDS="${DDOS_BASELINE_SECONDS:-30}"
export DDOS_DETECTOR_THRESHOLD="${DDOS_DETECTOR_THRESHOLD:-3}"
export DDOS_REQUIRED_CONSECUTIVE="${DDOS_REQUIRED_CONSECUTIVE:-2}"
export DDOS_CONTROLLER_APP="${DDOS_CONTROLLER_APP:-custom/ryu_ddos_controller.py}"
export DDOS_RUN_CONTROL="${DDOS_RUN_CONTROL:-$REPO_ROOT/results/current_run.json}"

ryu-manager \
  custom/ryu_ddos_controller.py \
  custom/ddos_monitor.py \
  --ofp-tcp-listen-port 6633