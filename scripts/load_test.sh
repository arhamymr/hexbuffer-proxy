#!/usr/bin/env bash
# load_test.sh — Load testing and profiling script for hexbuffer-proxy

set -euo pipefail

PORT=8080
TARGET_URL="http://127.0.0.1:${PORT}/"
CONCURRENCY=50
REQUESTS=1000

echo "=========================================================="
echo "         hexbuffer-proxy — Load & Performance Test         "
echo "=========================================================="

echo "[1/3] Building release binary..."
cargo build --release --quiet

echo "[2/3] Starting proxy on port ${PORT}..."
./target/release/hexbuffer-proxy --port ${PORT} &
PROXY_PID=$!

cleanup() {
    echo "Cleaning up proxy server process (PID ${PROXY_PID})..."
    kill "${PROXY_PID}" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for server startup
sleep 1.5

echo "[3/3] Running load test (${REQUESTS} requests, ${CONCURRENCY} concurrent connections)..."

if command -v hey &> /dev/null; then
    hey -n "${REQUESTS}" -c "${CONCURRENCY}" "${TARGET_URL}"
elif command -v wrk &> /dev/null; then
    wrk -t4 -c"${CONCURRENCY}" -d10s "${TARGET_URL}"
else
    echo "Note: Neither 'hey' nor 'wrk' found. Running fallback curl benchmarking loop..."
    START_TIME=$(date +%s%N)
    for i in $(seq 1 "${REQUESTS}"); do
        curl -s -o /dev/null "${TARGET_URL}" &
        if (( i % CONCURRENCY == 0 )); then
            wait
        fi
    done
    wait
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    RPS=$(( REQUESTS * 1000 / ELAPSED_MS ))
    echo "----------------------------------------------------------"
    echo " Completed ${REQUESTS} requests in ${ELAPSED_MS} ms"
    echo " Throughput: ~${RPS} requests/sec"
    echo "----------------------------------------------------------"
fi

echo "Load test completed successfully!"
