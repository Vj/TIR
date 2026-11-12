#!/system/bin/sh
# Read-only process inspection. Input is passed as $1 by the host runner.
PKG="$1"
case "$PKG" in
  ""|*[!A-Za-z0-9._]*)
    echo "ERROR=invalid package identifier"
    exit 2
    ;;
esac

PID="$(pidof "$PKG" 2>/dev/null | awk '{print $1}')"
if [ -z "$PID" ]; then
  echo "STATE=NOT_RUNNING"
  exit 0
fi

STATUS_FILE="/proc/$PID/status"
if [ ! -r "$STATUS_FILE" ]; then
  echo "ERROR=process status is not readable"
  exit 0
fi

TRACER_PID="$(sed -n 's/^TracerPid:[[:space:]]*//p' "$STATUS_FILE" | tr -d '[:space:]')"
case "$TRACER_PID" in
  ''|*[!0-9]*) echo "ERROR=TracerPid was unavailable"; exit 0 ;;
esac

echo "STATE=RUNNING"
echo "PID=$PID"
echo "TRACER_PID=$TRACER_PID"
