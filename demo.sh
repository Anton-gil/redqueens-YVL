#!/usr/bin/env bash
# Red Queen — one-command live demo.
#
# Starts the local web server AND the paced attack->defend loop together, so the frontend actually
# ANIMATES. (Opening frontend/index.html directly as a file:// URL will NOT animate — the browser
# blocks its fetch of state.json and it falls back to a static sample. You must use the http URL
# below while this script is running.)
#
# Usage:
#   bash demo.sh            # refresh real data, then run the live demo once
#   bash demo.sh 3 1.2      # 3 loops, 1.2s per beat
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PATH:$HOME/.foundry/bin"

PORT=8799

# clean any previous server on this port
pkill -f "orchestrator.server $PORT" 2>/dev/null || true
pkill -f "http.server $PORT" 2>/dev/null || true
sleep 1

# make sure there is real data to animate on the first START click
if [ ! -f orchestrator/state/state.json ]; then
  echo "[demo] priming real pipeline data (one-time) ..."
  python3 -m orchestrator.loop --pace 0.01 >/dev/null 2>&1 || true
fi

echo ""
echo "======================================================================"
echo "  OPEN THIS IN YOUR BROWSER:"
echo "    http://127.0.0.1:$PORT/frontend/index.html"
echo "  Then pick a TARGET and click  > START ATTACK  in the page."
echo "  (leave this terminal running; Ctrl+C to stop)"
echo "======================================================================"
echo ""

exec python3 -m orchestrator.server "$PORT"
