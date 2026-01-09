#!/bin/bash
#
# FuzzingBrain v2 - Evaluation Server & Dashboard
# One-click script to start/stop eval infrastructure
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON="$VENV_DIR/bin/python3"
PID_DIR="$SCRIPT_DIR/.eval_pids"
LOG_DIR="$SCRIPT_DIR/logs/eval"

# Default ports
EVAL_SERVER_PORT="${EVAL_SERVER_PORT:-18080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-18081}"

# MongoDB/Redis
MONGODB_URI="${MONGODB_URI:-mongodb://localhost:27017}"
REDIS_URL="${REDIS_URL:-redis://localhost:6379}"

# =============================================================================
# Colors
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

CLAUDE_ORANGE='\033[38;5;208m'
CLAUDE_BROWN='\033[38;5;172m'
CLAUDE_SAND='\033[38;5;180m'

# =============================================================================
# Banner
# =============================================================================
show_banner() {
    echo -e "${CLAUDE_ORANGE}"
    cat << 'EOF'
    ███████╗██╗   ██╗ █████╗ ██╗
    ██╔════╝██║   ██║██╔══██╗██║
    █████╗  ██║   ██║███████║██║
    ██╔══╝  ╚██╗ ██╔╝██╔══██║██║
    ███████╗ ╚████╔╝ ██║  ██║███████╗
    ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${CLAUDE_SAND}    ══════════════════════════════════════════════════${NC}"
    echo -e "${CLAUDE_ORANGE}         FuzzingBrain Evaluation Infrastructure${NC}"
    echo -e "${CLAUDE_SAND}    ══════════════════════════════════════════════════${NC}"
    echo ""
}

# =============================================================================
# Logging
# =============================================================================
print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step()  { echo -e "${CYAN}[STEP]${NC} $1"; }

# =============================================================================
# Helper Functions
# =============================================================================

check_port() {
    local port=$1
    if command -v nc &> /dev/null; then
        nc -z localhost $port 2>/dev/null && return 0
    fi
    if (echo > /dev/tcp/localhost/$port) 2>/dev/null; then
        return 0
    fi
    return 1
}

get_pid() {
    local service=$1
    local pid_file="$PID_DIR/${service}.pid"
    if [ -f "$pid_file" ]; then
        cat "$pid_file"
    fi
}

is_running() {
    local service=$1
    local pid=$(get_pid "$service")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    return 1
}

ensure_dirs() {
    mkdir -p "$PID_DIR"
    mkdir -p "$LOG_DIR"
}

check_venv() {
    if [ ! -f "$PYTHON" ]; then
        print_error "Virtual environment not found at $VENV_DIR"
        print_error "Please run ./FuzzingBrain.sh first to set up the environment"
        exit 1
    fi
}

check_mongodb() {
    local host=$(echo "$MONGODB_URI" | sed -E 's|mongodb://([^:]+):.*|\1|' | sed 's|mongodb://||')
    local port=$(echo "$MONGODB_URI" | sed -E 's|.*:([0-9]+).*|\1|')
    host=${host:-localhost}
    port=${port:-27017}

    if command -v nc &> /dev/null; then
        if nc -z "$host" "$port" 2>/dev/null; then
            return 0
        fi
    fi
    if (echo > /dev/tcp/$host/$port) 2>/dev/null; then
        return 0
    fi
    return 1
}

check_redis() {
    local host=$(echo "$REDIS_URL" | sed -E 's|redis://([^:]+):.*|\1|' | sed 's|redis://||')
    local port=$(echo "$REDIS_URL" | sed -E 's|.*:([0-9]+).*|\1|')
    host=${host:-localhost}
    port=${port:-6379}

    if command -v nc &> /dev/null; then
        if nc -z "$host" "$port" 2>/dev/null; then
            return 0
        fi
    fi
    if (echo > /dev/tcp/$host/$port) 2>/dev/null; then
        return 0
    fi
    return 1
}

# =============================================================================
# Start Services
# =============================================================================

start_eval_server() {
    if is_running "eval_server"; then
        print_warn "Eval server is already running (PID: $(get_pid eval_server))"
        return 0
    fi

    if check_port $EVAL_SERVER_PORT; then
        print_error "Port $EVAL_SERVER_PORT is already in use"
        return 1
    fi

    print_step "Starting Eval Server on port $EVAL_SERVER_PORT..."

    $PYTHON -m fuzzingbrain.eval_server \
        --host 0.0.0.0 \
        --port $EVAL_SERVER_PORT \
        --mongodb-uri "$MONGODB_URI" \
        --redis-url "$REDIS_URL" \
        > "$LOG_DIR/eval_server.log" 2>&1 &

    local pid=$!
    echo $pid > "$PID_DIR/eval_server.pid"

    # Wait for server to start
    for i in {1..10}; do
        sleep 1
        if check_port $EVAL_SERVER_PORT; then
            print_info "Eval Server started (PID: $pid)"
            return 0
        fi
    done

    print_error "Eval Server failed to start. Check $LOG_DIR/eval_server.log"
    return 1
}

start_dashboard() {
    if is_running "dashboard"; then
        print_warn "Dashboard is already running (PID: $(get_pid dashboard))"
        return 0
    fi

    if check_port $DASHBOARD_PORT; then
        print_error "Port $DASHBOARD_PORT is already in use"
        return 1
    fi

    print_step "Starting Dashboard on port $DASHBOARD_PORT..."

    $PYTHON -m fuzzingbrain.dashboard \
        --host 0.0.0.0 \
        --port $DASHBOARD_PORT \
        --eval-server "http://localhost:$EVAL_SERVER_PORT" \
        > "$LOG_DIR/dashboard.log" 2>&1 &

    local pid=$!
    echo $pid > "$PID_DIR/dashboard.pid"

    # Wait for server to start
    for i in {1..10}; do
        sleep 1
        if check_port $DASHBOARD_PORT; then
            print_info "Dashboard started (PID: $pid)"
            return 0
        fi
    done

    print_error "Dashboard failed to start. Check $LOG_DIR/dashboard.log"
    return 1
}

# =============================================================================
# Stop Services
# =============================================================================

stop_service() {
    local service=$1
    local pid=$(get_pid "$service")

    if [ -z "$pid" ]; then
        print_warn "$service is not running (no PID file)"
        return 0
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        print_warn "$service is not running (stale PID file)"
        rm -f "$PID_DIR/${service}.pid"
        return 0
    fi

    print_step "Stopping $service (PID: $pid)..."
    kill "$pid" 2>/dev/null

    # Wait for process to exit
    for i in {1..10}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            print_info "$service stopped"
            rm -f "$PID_DIR/${service}.pid"
            return 0
        fi
        sleep 1
    done

    # Force kill
    print_warn "Force killing $service..."
    kill -9 "$pid" 2>/dev/null
    rm -f "$PID_DIR/${service}.pid"
    print_info "$service stopped"
}

# =============================================================================
# Status
# =============================================================================

show_status() {
    echo ""
    echo -e "${WHITE}Service Status:${NC}"
    echo "─────────────────────────────────────────────"

    # Eval Server
    if is_running "eval_server"; then
        echo -e "  Eval Server:  ${GREEN}Running${NC} (PID: $(get_pid eval_server))"
        echo -e "                http://localhost:$EVAL_SERVER_PORT"
        echo -e "                API Docs: http://localhost:$EVAL_SERVER_PORT/docs"
    else
        echo -e "  Eval Server:  ${RED}Stopped${NC}"
    fi

    # Dashboard
    if is_running "dashboard"; then
        echo -e "  Dashboard:    ${GREEN}Running${NC} (PID: $(get_pid dashboard))"
        echo -e "                http://localhost:$DASHBOARD_PORT"
    else
        echo -e "  Dashboard:    ${RED}Stopped${NC}"
    fi

    echo "─────────────────────────────────────────────"

    # Dependencies
    echo ""
    echo -e "${WHITE}Dependencies:${NC}"
    if check_mongodb; then
        echo -e "  MongoDB:      ${GREEN}Available${NC} ($MONGODB_URI)"
    else
        echo -e "  MongoDB:      ${RED}Not Available${NC} ($MONGODB_URI)"
    fi

    if check_redis; then
        echo -e "  Redis:        ${GREEN}Available${NC} ($REDIS_URL)"
    else
        echo -e "  Redis:        ${YELLOW}Not Available${NC} ($REDIS_URL)"
    fi
    echo ""
}

# =============================================================================
# Usage
# =============================================================================

show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start       Start eval server and dashboard (default)"
    echo "  stop        Stop all services"
    echo "  restart     Restart all services"
    echo "  status      Show service status"
    echo "  logs        Show logs (tail -f)"
    echo ""
    echo "Options:"
    echo "  --eval-port <port>   Eval server port (default: $EVAL_SERVER_PORT)"
    echo "  --dashboard-port <port>  Dashboard port (default: $DASHBOARD_PORT)"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  EVAL_SERVER_PORT     Eval server port"
    echo "  DASHBOARD_PORT       Dashboard port"
    echo "  MONGODB_URI          MongoDB connection URI"
    echo "  REDIS_URL            Redis connection URL"
    echo ""
    echo "Examples:"
    echo "  $0                   # Start all services"
    echo "  $0 start             # Start all services"
    echo "  $0 stop              # Stop all services"
    echo "  $0 status            # Check status"
    echo "  $0 logs              # View logs"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

COMMAND="start"
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        start|stop|restart|status|logs)
            COMMAND="$1"
            shift
            ;;
        --eval-port)
            EVAL_SERVER_PORT="$2"
            shift 2
            ;;
        --dashboard-port)
            DASHBOARD_PORT="$2"
            shift 2
            ;;
        -h|--help)
            show_banner
            show_usage
            exit 0
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

show_banner
ensure_dirs
check_venv

case $COMMAND in
    start)
        print_step "Checking dependencies..."

        if ! check_mongodb; then
            print_error "MongoDB is not running!"
            print_error "Please start MongoDB first: ./FuzzingBrain.sh (it will auto-start MongoDB)"
            exit 1
        fi
        print_info "MongoDB is available"

        if ! check_redis; then
            print_warn "Redis is not running (some features may be limited)"
        else
            print_info "Redis is available"
        fi

        echo ""
        start_eval_server
        start_dashboard
        show_status
        ;;

    stop)
        stop_service "dashboard"
        stop_service "eval_server"
        print_info "All services stopped"
        ;;

    restart)
        stop_service "dashboard"
        stop_service "eval_server"
        sleep 2
        start_eval_server
        start_dashboard
        show_status
        ;;

    status)
        show_status
        ;;

    logs)
        echo "Showing logs (Ctrl+C to exit)..."
        echo ""
        tail -f "$LOG_DIR/eval_server.log" "$LOG_DIR/dashboard.log" 2>/dev/null || \
            print_error "No log files found. Start the services first."
        ;;

    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac
