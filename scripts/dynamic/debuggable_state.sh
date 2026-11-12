#!/system/bin/sh
# Read-only package flag inspection via package manager output.
PKG="$1"
case "$PKG" in
  ""|*[!A-Za-z0-9._]*)
    echo "ERROR=invalid package identifier"
    exit 2
    ;;
esac

DUMP="$(dumpsys package "$PKG" 2>/dev/null)"
if [ -z "$DUMP" ] || ! printf '%s\n' "$DUMP" | grep -q "Package \[$PKG\]"; then
  echo "ERROR=package was not found by package manager"
  exit 0
fi

if printf '%s\n' "$DUMP" | grep -E "pkgFlags=\[[^]]*DEBUGGABLE|flags=\[[^]]*DEBUGGABLE" >/dev/null; then
  echo "DEBUGGABLE=true"
else
  echo "DEBUGGABLE=false"
fi
