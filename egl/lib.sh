# Shared helpers for egl/run_step*.sh  (source it, don't run it)
#
#   start_ryu <logfile>   start the EGL controller, wait until it listens
#   stop_ryu              stop it (also called automatically on exit)
#   as_root <cmd...>      run a command with sudo, passing our variables
#                         explicitly (newer sudo ignores "sudo -E")

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RYU_ENV=${RYU_ENV:-$HOME/ryu-env}
export EVENTLET_NO_GREENDNS=yes
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$ROOT/results"
cd "$ROOT"

stop_ryu() {
  if [ -n "${RYU_PID:-}" ]; then kill "$RYU_PID" 2>/dev/null || true; wait "$RYU_PID" 2>/dev/null || true; fi
  RYU_PID=
  sudo mn -c >/dev/null 2>&1 || true
}
trap stop_ryu EXIT

start_ryu() {
  local log=$1
  stop_ryu
  "$RYU_ENV/bin/ryu-manager" --ofp-tcp-listen-port 6653 egl/egl_controller.py >"$log" 2>&1 &
  RYU_PID=$!
  for _ in $(seq 1 40); do
    (echo >/dev/tcp/127.0.0.1/6653) 2>/dev/null && return 0
    kill -0 "$RYU_PID" 2>/dev/null || { echo "Ryu died:"; tail -20 "$log"; exit 1; }
    sleep 0.5
  done
  echo "Ryu did not start listening on 6653"; exit 1
}

as_root() {
  sudo env "PATH=$PATH" "PYTHONPATH=$PYTHONPATH" \
    "EGL_TELEMETRY_CSV=${EGL_TELEMETRY_CSV:-}" "$@"
}
