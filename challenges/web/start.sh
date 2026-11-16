#!/usr/bin/env bash
# Start the Web challenge on 127.0.0.1 (default port 8080, 0 = ephemeral).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8080}"
cd "$ROOT"

if [[ -f .server.pid ]] && kill -0 "$(cat .server.pid)" 2>/dev/null; then
  echo "already running: pid $(cat .server.pid), port $(cat .server.port 2>/dev/null || echo unknown)"
  exit 0
fi

: > .server.log
python3 instructor/server.py --host 127.0.0.1 --port "$PORT" >> .server.log 2>&1 &
PID=$!
echo "$PID" > .server.pid

for _ in $(seq 1 80); do
  if grep -q '^LISTENING ' .server.log; then
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "server failed to start:" >&2
    cat .server.log >&2
    exit 1
  fi
  sleep 0.1
done

awk '/^LISTENING /{print $2; exit}' .server.log > .server.port
ACTUAL="$(cat .server.port)"
if [[ -z "$ACTUAL" ]]; then
  echo "server did not report a port:" >&2
  cat .server.log >&2
  exit 1
fi
echo "web challenge running at http://127.0.0.1:${ACTUAL} (pid ${PID})"
