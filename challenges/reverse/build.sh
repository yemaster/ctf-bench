#!/usr/bin/env bash
# Rebuild the Reverse challenge binary from instructor sources.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
python3 instructor/build.py
