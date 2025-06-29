#!/bin/bash

# Script to run integration tests with server
set -e

echo "Starting server in background..."
./build/naabu-api &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
sleep 3

# Check if server is running
if ! curl -s http://localhost:8080/health >/dev/null; then
    echo "Server failed to start"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "Server started successfully"

# Run integration tests
echo "Running integration tests..."
if go test -run TestAsyncScanWorkflow -v .; then
    echo "Integration tests passed!"
else
    echo "Integration tests failed!"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Clean shutdown
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo "Done!"