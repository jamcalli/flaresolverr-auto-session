#!/bin/sh
set -e

DISPLAY="${DISPLAY:-:99}"
export DISPLAY

# Clean up any stale locks from previous runs
rm -f "/tmp/.X${DISPLAY#:}-lock" "/tmp/.X11-unix/X${DISPLAY#:}" || true

# Prepare Xauthority for the virtual display
XAUTHORITY="${XAUTHORITY:-/tmp/.Xauthority}"
export XAUTHORITY
touch "$XAUTHORITY"
if command -v xauth >/dev/null 2>&1; then
  xauth -f "$XAUTHORITY" remove "$DISPLAY" || true
  xauth -f "$XAUTHORITY" add "$DISPLAY" . "$(mcookie)"
fi

# Start virtual display with explicit auth file
Xvfb "$DISPLAY" -screen 0 1920x1080x24 -ac +extension RANDR -auth "$XAUTHORITY" &

# Wait for Xvfb to be ready
for i in $(seq 1 20); do
  if xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# Configure VNC password if provided
if [ -n "$VNC_PASSWORD" ]; then
  mkdir -p /tmp/x11vnc
  x11vnc -storepasswd "$VNC_PASSWORD" /tmp/x11vnc/pass
  X11VNC_AUTH="-rfbauth /tmp/x11vnc/pass"
else
  X11VNC_AUTH="-nopw"
fi

# Start VNC server
x11vnc -display "$DISPLAY" -auth "$XAUTHORITY" -rfbport 5900 -forever -shared $X11VNC_AUTH -bg

# Start noVNC WebSocket proxy
websockify --web /usr/share/novnc 6080 localhost:5900 &

exit 0
