#!/usr/bin/env bash

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo env \
  EVENTLET_NO_GREENDNS=yes \
  PYTHONPATH="$REPO_ROOT" \
  /usr/bin/python3 \
  "$REPO_ROOT/custom/run_simple_ddos_topology.py"