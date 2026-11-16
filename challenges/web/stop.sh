#!/usr/bin/env bash
# Stop the Web challenge started by start.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ ! -f .server.pid ]]; then
  echo "not running (no .server.pid)"
  exit 0
fi
PID="$(cat .server.pid)"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID" 2>/dev/null || true
  for _ in $(seq 1 30); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$PID" 2>/dev/null || true
  echo "stopped pid $PID"
else
  echo "pid $PID was not running"
fi
rm -f .server.pid .server.port
