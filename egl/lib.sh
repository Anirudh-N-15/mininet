# Shared helpers for egl/run_step*.sh  (source it, don't run it)
#
#   start_ryu <logfile> [apps...]   start Ryu (default app: egl.egl_controller),
#                         wait until it listens
#   plot <module> [args]  draw a figure with the Ryu env's python (has matplotlib)
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
  local log=$1; shift
  local apps=("$@")
  [ ${#apps[@]} -gt 0 ] || apps=(egl.egl_controller)
  stop_ryu
  if ! sudo ovs-vsctl show >/dev/null 2>&1; then
    echo "Open vSwitch is not running. Start it with:"
    echo "  sudo service openvswitch-switch start"
    exit 1
  fi
  # apps are loaded by MODULE name (egl.x), so all of them share one copy of
  # each event class -- loading by file path can break event delivery
  "$RYU_ENV/bin/ryu-manager" --ofp-tcp-listen-port 6653 "${apps[@]}" >"$log" 2>&1 &
  RYU_PID=$!
  for _ in $(seq 1 40); do
    (echo >/dev/tcp/127.0.0.1/6653) 2>/dev/null && return 0
    kill -0 "$RYU_PID" 2>/dev/null || { echo "Ryu died:"; tail -20 "$log"; exit 1; }
    sleep 0.5
  done
  echo "Ryu did not start listening on 6653"; exit 1
}

plot() {
  local py="$RYU_ENV/bin/python"
  "$py" -c "import matplotlib" 2>/dev/null || py=python3
  "$py" -m "$@" || echo "(plot skipped: install matplotlib, e.g. $RYU_ENV/bin/pip install matplotlib)"
}

as_root() {
  sudo env "PATH=$PATH" "PYTHONPATH=$PYTHONPATH" \
    "EGL_TELEMETRY_CSV=${EGL_TELEMETRY_CSV:-}" \
    "EGL_DETECTOR_CSV=${EGL_DETECTOR_CSV:-}" "$@"
}
