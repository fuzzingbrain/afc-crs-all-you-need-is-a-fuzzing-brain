#!/bin/bash
#
# FuzzingBrain v2 - Create Work Configuration
# Generate a task configuration file from template
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/work"

# =============================================================================
# Colors
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

CLAUDE_ORANGE='\033[38;5;208m'

# =============================================================================
# Logging
# =============================================================================
print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Templates
# =============================================================================

create_full_scan_template() {
    local name="$1"
    local file="$WORK_DIR/${name}.json"

    cat > "$file" << 'EOF'
{
    "_comment": "=== FuzzingBrain Full Scan Configuration ===",
    "_instructions": [
        "1. Fill in 'repo_url' with the git repository URL",
        "2. Set 'project_name' (used for workspace naming)",
        "3. Set 'fuzzer_filter' to specify which fuzzers to run (empty = all)",
        "4. Adjust 'timeout_minutes' as needed",
        "5. Run: ./FuzzingBrain.sh work/<name>.json"
    ],

    "repo_url": "https://github.com/YOUR_USERNAME/YOUR_REPO.git",
    "project_name": "YOUR_PROJECT_NAME",

    "task_type": "pov",
    "scan_mode": "full",

    "fuzzer_filter": [],
    "sanitizers": ["address"],
    "timeout_minutes": 30,

    "_optional_fields": "=== Below are optional fields ===",

    "target_commit": null,
    "ossfuzz_project_name": null,
    "fuzz_tooling_url": null,
    "fuzz_tooling_ref": null,

    "budget_limit": 50,
    "eval_server": null,
    "pov_count": 1
}
EOF
    echo "$file"
}

create_delta_scan_template() {
    local name="$1"
    local file="$WORK_DIR/${name}.json"

    cat > "$file" << 'EOF'
{
    "_comment": "=== FuzzingBrain Delta Scan Configuration ===",
    "_instructions": [
        "1. Fill in 'repo_url' with the git repository URL",
        "2. Set 'project_name' (used for workspace naming)",
        "3. Set 'base_commit' (the known-good commit)",
        "4. Set 'delta_commit' (the commit to analyze, default HEAD)",
        "5. Set 'fuzzer_filter' to specify which fuzzers to run (empty = all)",
        "6. Run: ./FuzzingBrain.sh work/<name>.json"
    ],

    "repo_url": "https://github.com/YOUR_USERNAME/YOUR_REPO.git",
    "project_name": "YOUR_PROJECT_NAME",

    "task_type": "pov",
    "scan_mode": "delta",

    "base_commit": "BASE_COMMIT_HASH_HERE",
    "delta_commit": "DELTA_COMMIT_HASH_OR_HEAD",

    "fuzzer_filter": [],
    "sanitizers": ["address"],
    "timeout_minutes": 30,

    "_optional_fields": "=== Below are optional fields ===",

    "ossfuzz_project_name": null,
    "fuzz_tooling_url": null,
    "fuzz_tooling_ref": null,

    "budget_limit": 50,
    "eval_server": null,
    "pov_count": 1
}
EOF
    echo "$file"
}

# =============================================================================
# Usage
# =============================================================================

show_usage() {
    echo -e "${CLAUDE_ORANGE}"
    cat << 'EOF'
     ██████╗██████╗ ███████╗ █████╗ ████████╗███████╗
    ██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝
    ██║     ██████╔╝█████╗  ███████║   ██║   █████╗
    ██║     ██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══╝
    ╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗
     ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
    ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
    ██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
    ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
    ██║███╗██║██║   ██║██╔══██╗██╔═██╗
    ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
     ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
EOF
    echo -e "${NC}"
    echo ""
    echo "Usage: $0 <template> <name>"
    echo ""
    echo "Templates:"
    echo "  full        Full scan - analyze entire codebase"
    echo "  delta       Delta scan - analyze changes between commits"
    echo ""
    echo "Arguments:"
    echo "  <name>      Name for the configuration (without .json)"
    echo ""
    echo "Examples:"
    echo "  $0 full myproject        # Create work/myproject.json (full scan)"
    echo "  $0 delta libpng-fix      # Create work/libpng-fix.json (delta scan)"
    echo ""
    echo "After creating:"
    echo "  1. Edit the generated JSON file in work/<name>.json"
    echo "  2. Run: ./FuzzingBrain.sh work/<name>.json"
    echo ""
    echo "List existing configurations:"
    echo "  $0 list"
    echo ""
}

list_configs() {
    echo -e "${WHITE}Existing configurations in work/:${NC}"
    echo "─────────────────────────────────────────────"

    if [ ! -d "$WORK_DIR" ] || [ -z "$(ls -A "$WORK_DIR"/*.json 2>/dev/null)" ]; then
        echo "  (none)"
    else
        for f in "$WORK_DIR"/*.json; do
            local name=$(basename "$f" .json)
            local scan_mode=$(grep -o '"scan_mode"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null | sed 's/.*"\([^"]*\)"/\1/')
            local task_type=$(grep -o '"task_type"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null | sed 's/.*"\([^"]*\)"/\1/')
            printf "  ${CYAN}%-20s${NC} [%s, %s]\n" "$name" "${scan_mode:-?}" "${task_type:-?}"
        done
    fi
    echo ""
    echo "Run a config: ./FuzzingBrain.sh work/<name>.json"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

# Show usage if no args
if [ $# -eq 0 ]; then
    show_usage
    exit 0
fi

# Handle list command
if [ "$1" = "list" ]; then
    list_configs
    exit 0
fi

# Handle help
if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
    show_usage
    exit 0
fi

# Check arguments
if [ $# -lt 2 ]; then
    print_error "Missing arguments"
    echo ""
    show_usage
    exit 1
fi

TEMPLATE="$1"
NAME="$2"

# Create work directory
mkdir -p "$WORK_DIR"

# Check if file already exists
if [ -f "$WORK_DIR/${NAME}.json" ]; then
    print_warn "File already exists: work/${NAME}.json"
    read -p "Overwrite? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cancelled"
        exit 0
    fi
fi

# Create template
case "$TEMPLATE" in
    full)
        FILE=$(create_full_scan_template "$NAME")
        print_info "Created full scan template: $FILE"
        ;;
    delta)
        FILE=$(create_delta_scan_template "$NAME")
        print_info "Created delta scan template: $FILE"
        ;;
    *)
        print_error "Unknown template: $TEMPLATE"
        echo ""
        echo "Available templates: full, delta"
        exit 1
        ;;
esac

echo ""
echo -e "${WHITE}Next steps:${NC}"
echo "  1. Edit the configuration:"
echo -e "     ${CYAN}vim work/${NAME}.json${NC}"
echo ""
echo "  2. Run FuzzingBrain:"
echo -e "     ${CYAN}./FuzzingBrain.sh work/${NAME}.json${NC}"
echo ""
echo "  (Optional) With evaluation:"
echo -e "     ${CYAN}./eval.sh${NC}                                    # Start eval server first"
echo -e "     ${CYAN}./FuzzingBrain.sh --eval-port 18080 work/${NAME}.json${NC}"
echo ""
