#!/usr/bin/env bash
# ==============================================================================
# Autonomous Network Engineer - Unified Launcher (Run Everything at Once)
# ==============================================================================
# Usage:
#   sudo ./run_all.sh
#   sudo ./run_all.sh --mode approval
#   sudo ./run_all.sh --dry-run
# ==============================================================================
set -e

# Change directory to this script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==========================================================="
echo "   AUTONOMOUS NETWORK ENGINEER - ALL-IN-ONE RUNNER         "
echo "==========================================================="

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run with sudo: sudo ./run_all.sh"
    exit 1
fi

# Detect python executable (venv or system)
if [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
    PY="$SCRIPT_DIR/venv/bin/python"
elif [ -f "$SCRIPT_DIR/../venv/bin/python" ]; then
    PY="$SCRIPT_DIR/../venv/bin/python"
else
    PY="$(which python3)"
fi
echo "[+] Using Python: $PY"

# 1. Start Open vSwitch
echo "[+] Starting Open vSwitch service..."
service openvswitch-switch start || true

# 2. Check / Train Models if missing
if [ ! -f "$SCRIPT_DIR/models/isolation_forest.joblib" ] || [ ! -f "$SCRIPT_DIR/models/random_forest.joblib" ]; then
    echo "[!] Trained ML models not found in $SCRIPT_DIR/models/"
    if [ ! -f "$SCRIPT_DIR/data/dataset.csv" ]; then
        echo "[+] Generating initial training dataset..."
        "$PY" "$SCRIPT_DIR/generate_synthetic_dataset.py" || true
    fi
    echo "[+] Training ML models (Isolation Forest + Random Forest)..."
    "$PY" "$SCRIPT_DIR/train_models.py" || true
fi

# 3. Clean up any previous Mininet instances
echo "[+] Cleaning up Mininet..."
mn -c > /dev/null 2>&1 || true

# Trap termination to kill child processes and cleanup
cleanup() {
    echo ""
    echo "[!] Shutting down all services..."
    if [ -n "$WEB_PID" ] && kill -0 "$WEB_PID" 2>/dev/null; then
        echo "[+] Stopping Web App (PID: $WEB_PID)..."
        kill "$WEB_PID" 2>/dev/null || true
    fi
    if [ -n "$MONITOR_PID" ] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        echo "[+] Stopping Network Monitor (PID: $MONITOR_PID)..."
        kill -INT "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
    echo "[+] Cleaning up Mininet network interfaces..."
    mn -c > /dev/null 2>&1 || true
    echo "[+] All components stopped cleanly. Goodbye!"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 4. Start the simulated network monitor in the background
echo "[+] Starting Simulated Network Monitor (Mininet + ML Healer)..."
"$PY" "$SCRIPT_DIR/run_monitor.py" "$@" &
MONITOR_PID=$!
echo "[+] Monitor started with PID $MONITOR_PID"

# 5. Wait for monitor to initialize network and create status.json
echo "[+] Waiting for network topology and services to initialize..."
for i in {1..20}; do
    if [ -f "$SCRIPT_DIR/data/status.json" ]; then
        break
    fi
    sleep 1
done

# 6. Start the Web Application
echo "[+] Starting Flask Web Application on http://127.0.0.1:5000 ..."
echo "-----------------------------------------------------------"
echo "  DASHBOARD URL: http://127.0.0.1:5000"
echo "  First visit: Create your administrator login on /setup"
echo "  Press Ctrl+C to stop the entire project cleanly."
echo "-----------------------------------------------------------"

# Run web app in foreground so user sees logs and Ctrl+C triggers cleanup
"$PY" "$SCRIPT_DIR/web_app.py" &
WEB_PID=$!

# Wait for both processes
wait $WEB_PID $MONITOR_PID
