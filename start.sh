#!/usr/bin/env bash
# Start the local CTF benchmark judge.
#
# Defaults are aimed at the Qiming Docker deployment on this host:
#   * API listens on the qiming_default bridge gateway (auto-detected)
#   * Web challenge instances bind the same address, so the agent container
#     can reach them at http://172.18.0.1:<random-port>
#
# Examples:
#   ./start.sh                     # normal use
#   ./start.sh --reset             # clear scores, keep the token
#   ./start.sh --bind 0.0.0.0      # also reachable from the LAN
#   ./start.sh --port 9000         # another port
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/server.py" "$@"
