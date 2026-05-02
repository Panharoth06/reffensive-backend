#!/bin/bash
set -e

echo "Starting development environment..."

# Start Redis in background
echo "Starting Redis..."
docker compose up -d redis
echo "Wait for 2 seconds..."
sleep 2

# Start Go server in background
echo "Starting Go server..."
go run go-server/cmd/main.go &
GO_PID=$!

# Wait for Go server to be ready
echo "Waiting for Go server to start..."
sleep 3

# Start FastAPI gateway
echo "Starting FastAPI gateway..."
uv run uvicorn fastapi-gateway.main:app --reload &
UVICORN_PID=$!

# Trap to cleanup on exit
cleanup() {
    echo "Shutting down services..."
    kill $GO_PID 2>/dev/null  true
    kill $UVICORN_PID 2>/dev/null  true
    docker compose down
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "All services started (Go: $GO_PID, Uvicorn: $UVICORN_PID)"
echo "Press Ctrl+C to stop all services"

# Wait for background processes
wait