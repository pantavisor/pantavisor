#!/bin/bash
#
# End-to-end test: pvcm-proxy <-> Zephyr native_sim via PTY
#
# The native_sim UART reads from stdin and writes to a PTY.
# pvcm-proxy reads from the PTY and writes to a named pipe
# which is connected to Zephyr's stdin.
#
# Usage: ./run-native-test.sh <path-to-zephyr.exe> [path-to-pvcm-proxy]

set -e

ZEPHYR_EXE="${1:?Usage: $0 <zephyr.exe> [pvcm-proxy]}"
PROXY="${2:-/tmp/pvcm-proxy-test}"

PIPE="/tmp/pvcm-test-pipe"
ZLOG="/tmp/zephyr-test.log"
PLOG="/tmp/proxy-test.log"

cleanup() {
    kill $ZP $PP 2>/dev/null
    rm -f "$PIPE" /tmp/pvcm-test-run.json
}
trap cleanup EXIT

# Create named pipe for pvcm-proxy stdout -> Zephyr stdin
rm -f "$PIPE"
mkfifo "$PIPE"

# Start Zephyr: reads from pipe, writes to PTY + log
/lib64/ld-linux-x86-64.so.2 "$ZEPHYR_EXE" --rt < "$PIPE" > "$ZLOG" 2>&1 &
ZP=$!
sleep 2

# Get PTY path
PTY=$(grep -o '/dev/pts/[0-9]*' "$ZLOG" | head -1)
if [ -z "$PTY" ]; then
    echo "ERROR: no PTY found in Zephyr output"
    cat "$ZLOG"
    exit 1
fi
echo "Zephyr PID=$ZP PTY=$PTY"

# Create run.json for pvcm-proxy (reads from PTY)
cat > /tmp/pvcm-test-run.json <<EOF
{"name":"test","type":"mcu","mcu":{"device":"$PTY","transport":"uart","baudrate":921600}}
EOF

# Start pvcm-proxy: reads from PTY, writes to pipe (-> Zephyr stdin)
# stderr goes to terminal for debugging
"$PROXY" --name test --config /tmp/pvcm-test-run.json > "$PIPE" 2>"$PLOG" &
PP=$!

echo "pvcm-proxy PID=$PP"
echo "Waiting 15 seconds..."
sleep 15

echo ""
echo "=== pvcm-proxy log ==="
cat "$PLOG"
echo ""
echo "=== Zephyr log ==="
cat "$ZLOG"
