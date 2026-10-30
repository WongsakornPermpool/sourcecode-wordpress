#!/bin/bash
set -eu

DIR="/home/doramonlnwza/log-dashboard"
LOG="/var/log/nginx/access.log"
REPORT="$DIR/ai_scan_report.json"
TMP="$DIR/ai_scan_report.json.tmp"

trap 'rm -f "$TMP"' EXIT

/home/doramonlnwza/venvs/logml/bin/python "$DIR/scan_logs.py" < "$LOG" > "$TMP"

/usr/bin/python3 -m json.tool "$TMP" > /dev/null
chmod 644 "$TMP"
mv "$TMP" "$REPORT"

echo "Log report updated successfully: $(date -Is)"
