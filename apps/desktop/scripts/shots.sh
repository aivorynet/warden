#!/bin/sh
# Screenshot every screen in mock mode. Needs `npm run serve` (port 8765 here) and Edge.
EDGE="${EDGE:-/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe}"
PORT="${PORT:-8765}"
cd "$(dirname "$0")/.." || exit 1
for s in pledge unlock kit tokens detail wizard/3 settings inbox audit down; do
  f="shots/$(echo "$s" | tr / -).png"
  "$EDGE" --headless=new --disable-gpu --window-size=1280,820 --virtual-time-budget=4000 --screenshot="$(cygpath -w "$PWD/$f")" "http://localhost:$PORT/#$s" >/dev/null 2>&1
done
