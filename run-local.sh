#!/usr/bin/env bash
# run-local.sh — Start all Vecta KMS microservices locally (no Docker)
# Usage: ./run-local.sh        (starts all services)
#        ./run-local.sh stop   (kills all services)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_DIR="$ROOT_DIR/local-data/pids"
LOG_DIR="$ROOT_DIR/local-data/logs"
DATA_DIR="$ROOT_DIR/local-data"

mkdir -p "$PID_DIR" "$LOG_DIR"

# ── Common environment ──────────────────────────────────────────────
export POSTGRES_DSN="postgres://postgres:postgres@localhost:5432/vecta?sslmode=disable"
export NATS_URL="nats://localhost:4222"
export CONSUL_HTTP_ADDR="127.0.0.1:8500"
export REDIS_URL="redis://localhost:6379"
export VECTA_ENV="dev"
export SQLITE_FALLBACK="false"

# Auth bootstrap defaults
export AUTH_BOOTSTRAP_TENANT_ID="root"
export AUTH_BOOTSTRAP_TENANT_NAME="Root"
export AUTH_BOOTSTRAP_ADMIN_USERNAME="admin"
export AUTH_BOOTSTRAP_ADMIN_PASSWORD="VectaAdmin@2026"
export AUTH_BOOTSTRAP_ADMIN_EMAIL="admin@vecta.local"
export AUTH_BOOTSTRAP_FORCE_PASSWORD_CHANGE="true"

stop_all() {
    echo "Stopping all services..."
    if [ -d "$PID_DIR" ]; then
        for pidfile in "$PID_DIR"/*.pid; do
            [ -f "$pidfile" ] || continue
            pid=$(cat "$pidfile")
            svc=$(basename "$pidfile" .pid)
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null && echo "  stopped $svc (pid $pid)"
            fi
            rm -f "$pidfile"
        done
    fi
    echo "All services stopped."
}

if [ "${1:-}" = "stop" ]; then
    stop_all
    exit 0
fi

# Stop any previously running instances
stop_all 2>/dev/null || true

# ── Bootstrap NATS JetStream ────────────────────────────────────────
# Create a unified AUDIT stream so all services can publish audit events.
echo "Bootstrapping NATS JetStream streams..."
go run "$ROOT_DIR/scripts/nats-bootstrap.go" 2>/dev/null && echo "  ✓ JetStream streams ready" || echo "  ⚠ JetStream bootstrap skipped (NATS may be unavailable)"

# ── Helper to start a service ───────────────────────────────────────
start_service() {
    local name="$1"
    local http_port="$2"
    local grpc_port="$3"
    shift 3
    # Any remaining args are extra env vars in KEY=VALUE form

    local svc_dir="$ROOT_DIR/services/$name"
    local log_file="$LOG_DIR/$name.log"
    local pid_file="$PID_DIR/$name.pid"
    local data_path="$DATA_DIR/$name"

    mkdir -p "$data_path"

    (
        cd "$ROOT_DIR"
        export HTTP_PORT="$http_port"
        export GRPC_PORT="$grpc_port"

        # Set extra env vars
        for kv in "$@"; do
            export "$kv"
        done

        go run "./services/$name" >> "$log_file" 2>&1 &
        echo $! > "$pid_file"
    )

    echo "  ✓ $name → http://localhost:$http_port  (grpc :$grpc_port)  [log: local-data/logs/$name.log]"
}

echo "═══════════════════════════════════════════════════════════════"
echo "  Vecta KMS — Local Development (no Docker)"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Infrastructure:"
echo "  PostgreSQL ─ localhost:5432 (vecta)"
echo "  NATS       ─ localhost:4222"
echo "  Consul     ─ localhost:8500"
echo "  Valkey     ─ localhost:6379"
echo ""
echo "Starting microservices..."
echo ""

# ── Core services (always needed) ───────────────────────────────────
start_service auth             8001 18001
start_service keycore          8010 18010 "KEYCORE_MEK_FILE=$DATA_DIR/keycore/mek.b64"
start_service audit            8070 18070
start_service policy           8040 18040

# ── Feature services ────────────────────────────────────────────────
start_service secrets          8020 18020
start_service certs            8030 18030
start_service governance       8050 18050
start_service pqc              8060 18060
start_service cloud            8080 18080
start_service compliance       8110 18110
start_service hyok             8120 18120
start_service ekm              8130 18130
start_service reporting        8140 18140
start_service qkd              8150 18150
start_service kmip             8160 18160
start_service payment          8170 18170
start_service sbom             8180 18180
start_service mpc              8190 18190
start_service dataprotect      8200 18200
start_service cluster-manager  8210 18210
start_service posture          8220 18220
start_service software-vault   8440 18440
start_service discovery        8100 18100
start_service ai               8090 18090

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  All services started!"
echo ""
echo "  Dashboard:  cd web/dashboard && npm run dev"
echo "              → http://localhost:5173"
echo ""
echo "  Login:      admin / VectaAdmin@2026"
echo ""
echo "  Logs:       tail -f local-data/logs/*.log"
echo "  Stop:       ./run-local.sh stop"
echo "═══════════════════════════════════════════════════════════════"

# Wait for Ctrl-C, then clean up
trap 'stop_all; exit 0' INT TERM
echo ""
echo "Press Ctrl+C to stop all services..."
wait
