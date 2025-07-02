#!/bin/bash

# Background Agent Configuration Script for Bug Hunting Framework
# This script configures and manages background agents for the bug hunting framework

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"

# Default agent configurations
DEFAULT_AGENT_CONFIGS=(
    "AGENT_ID=bug-hunting-agent-001"
    "AGENT_NAME=Bug Hunting Framework Agent"
    "AGENT_VERSION=1.0.0"
    "AGENT_ENVIRONMENT=development"
    "AGENT_MAX_CONCURRENT_TASKS=5"
    "AGENT_TASK_TIMEOUT_SECONDS=3600"
    "AGENT_HEARTBEAT_INTERVAL_SECONDS=30"
    "AGENT_RETRY_ATTEMPTS=3"
    "AGENT_RETRY_DELAY_SECONDS=60"
    "AGENT_MAX_MEMORY_MB=2048"
    "AGENT_MAX_CPU_PERCENT=80"
    "AGENT_DISK_QUOTA_GB=10"
    "AGENT_WORKER_REPLICAS=2"
    "AGENT_WORKER_MEMORY_MB=1024"
    "AGENT_WORKER_CPU_PERCENT=50"
    "AGENT_LOG_LEVEL=INFO"
    "AGENT_ENABLE_METRICS_COLLECTION=true"
    "AGENT_METRICS_PORT=9091"
    "AGENT_AUTO_RECOVERY_ENABLED=true"
    "AGENT_DEBUG_MODE=false"
)

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_status "Docker is running"
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        print_error "Docker Compose is not available. Please install Docker Compose and try again."
        exit 1
    fi
    print_status "Docker Compose is available"
}

# Function to create or update .env file
setup_env_file() {
    print_header "Setting up environment configuration"
    
    if [ ! -f "$ENV_FILE" ]; then
        print_status "Creating .env file from .env.example"
        cp "$PROJECT_ROOT/.env.example" "$ENV_FILE"
    else
        print_status ".env file already exists"
    fi
    
    # Add agent configurations if they don't exist
    for config in "${DEFAULT_AGENT_CONFIGS[@]}"; do
        key=$(echo "$config" | cut -d'=' -f1)
        value=$(echo "$config" | cut -d'=' -f2-)
        
        if ! grep -q "^$key=" "$ENV_FILE"; then
            echo "$config" >> "$ENV_FILE"
            print_status "Added $key configuration"
        fi
    done
}

# Function to configure agent scaling
configure_agent_scaling() {
    print_header "Configuring agent scaling"
    
    read -p "Enter number of worker agents (default: 2): " worker_count
    worker_count=${worker_count:-2}
    
    read -p "Enter memory limit per worker in MB (default: 1024): " worker_memory
    worker_memory=${worker_memory:-1024}
    
    read -p "Enter CPU limit per worker in percent (default: 50): " worker_cpu
    worker_cpu=${worker_cpu:-50}
    
    # Update .env file
    sed -i.bak "s/AGENT_WORKER_REPLICAS=.*/AGENT_WORKER_REPLICAS=$worker_count/" "$ENV_FILE"
    sed -i.bak "s/AGENT_WORKER_MEMORY_MB=.*/AGENT_WORKER_MEMORY_MB=$worker_memory/" "$ENV_FILE"
    sed -i.bak "s/AGENT_WORKER_CPU_PERCENT=.*/AGENT_WORKER_CPU_PERCENT=$worker_cpu/" "$ENV_FILE"
    
    print_status "Agent scaling configured: $worker_count workers, ${worker_memory}MB memory, ${worker_cpu}% CPU"
}

# Function to configure agent performance
configure_agent_performance() {
    print_header "Configuring agent performance"
    
    read -p "Enter max concurrent tasks (default: 5): " max_tasks
    max_tasks=${max_tasks:-5}
    
    read -p "Enter task timeout in seconds (default: 3600): " task_timeout
    task_timeout=${task_timeout:-3600}
    
    read -p "Enter heartbeat interval in seconds (default: 30): " heartbeat_interval
    heartbeat_interval=${heartbeat_interval:-30}
    
    read -p "Enter retry attempts (default: 3): " retry_attempts
    retry_attempts=${retry_attempts:-3}
    
    # Update .env file
    sed -i.bak "s/AGENT_MAX_CONCURRENT_TASKS=.*/AGENT_MAX_CONCURRENT_TASKS=$max_tasks/" "$ENV_FILE"
    sed -i.bak "s/AGENT_TASK_TIMEOUT_SECONDS=.*/AGENT_TASK_TIMEOUT_SECONDS=$task_timeout/" "$ENV_FILE"
    sed -i.bak "s/AGENT_HEARTBEAT_INTERVAL_SECONDS=.*/AGENT_HEARTBEAT_INTERVAL_SECONDS=$heartbeat_interval/" "$ENV_FILE"
    sed -i.bak "s/AGENT_RETRY_ATTEMPTS=.*/AGENT_RETRY_ATTEMPTS=$retry_attempts/" "$ENV_FILE"
    
    print_status "Agent performance configured"
}

# Function to configure agent monitoring
configure_agent_monitoring() {
    print_header "Configuring agent monitoring"
    
    read -p "Enable metrics collection? (y/n, default: y): " enable_metrics
    enable_metrics=${enable_metrics:-y}
    
    if [[ $enable_metrics =~ ^[Yy]$ ]]; then
        sed -i.bak "s/AGENT_ENABLE_METRICS_COLLECTION=.*/AGENT_ENABLE_METRICS_COLLECTION=true/" "$ENV_FILE"
        print_status "Metrics collection enabled"
    else
        sed -i.bak "s/AGENT_ENABLE_METRICS_COLLECTION=.*/AGENT_ENABLE_METRICS_COLLECTION=false/" "$ENV_FILE"
        print_status "Metrics collection disabled"
    fi
    
    read -p "Enter metrics port (default: 9091): " metrics_port
    metrics_port=${metrics_port:-9091}
    sed -i.bak "s/AGENT_METRICS_PORT=.*/AGENT_METRICS_PORT=$metrics_port/" "$ENV_FILE"
    
    read -p "Enter log level (DEBUG/INFO/WARNING/ERROR, default: INFO): " log_level
    log_level=${log_level:-INFO}
    sed -i.bak "s/AGENT_LOG_LEVEL=.*/AGENT_LOG_LEVEL=$log_level/" "$ENV_FILE"
    
    print_status "Agent monitoring configured"
}

# Function to configure agent security
configure_agent_security() {
    print_header "Configuring agent security"
    
    read -p "Enter JWT token rotation interval in hours (default: 1): " jwt_rotation_interval
    jwt_rotation_interval=${jwt_rotation_interval:-1}
    
    read -p "Enter token refresh threshold in minutes (default: 15): " token_refresh_threshold
    token_refresh_threshold=${token_refresh_threshold:-15}
    
    read -p "Enable SSL verification? (y/n, default: y): " enable_ssl
    enable_ssl=${enable_ssl:-y}
    
    # Update .env file
    sed -i.bak "s/AGENT_JWT_TOKEN_ROTATION_INTERVAL_HOURS=.*/AGENT_JWT_TOKEN_ROTATION_INTERVAL_HOURS=$jwt_rotation_interval/" "$ENV_FILE"
    sed -i.bak "s/AGENT_TOKEN_REFRESH_THRESHOLD_MINUTES=.*/AGENT_TOKEN_REFRESH_THRESHOLD_MINUTES=$token_refresh_threshold/" "$ENV_FILE"
    
    if [[ $enable_ssl =~ ^[Yy]$ ]]; then
        sed -i.bak "s/AGENT_ENABLE_SSL_VERIFICATION=.*/AGENT_ENABLE_SSL_VERIFICATION=true/" "$ENV_FILE"
        print_status "SSL verification enabled"
    else
        sed -i.bak "s/AGENT_ENABLE_SSL_VERIFICATION=.*/AGENT_ENABLE_SSL_VERIFICATION=false/" "$ENV_FILE"
        print_status "SSL verification disabled"
    fi
    
    print_status "Agent security configured"
}

# Function to start agents
start_agents() {
    print_header "Starting background agents"
    
    cd "$PROJECT_ROOT"
    
    # Start the agent services
    print_status "Starting agent coordinator and workers..."
    docker-compose up -d agent_coordinator agent_worker
    
    # Wait for services to be healthy
    print_status "Waiting for agents to be healthy..."
    sleep 30
    
    # Check agent status
    check_agent_status
}

# Function to stop agents
stop_agents() {
    print_header "Stopping background agents"
    
    cd "$PROJECT_ROOT"
    
    print_status "Stopping agent services..."
    docker-compose stop agent_coordinator agent_worker
    
    print_status "Agents stopped"
}

# Function to restart agents
restart_agents() {
    print_header "Restarting background agents"
    
    stop_agents
    sleep 5
    start_agents
}

# Function to check agent status
check_agent_status() {
    print_header "Checking agent status"
    
    cd "$PROJECT_ROOT"
    
    print_status "Agent containers:"
    docker-compose ps agent_coordinator agent_worker
    
    print_status "Agent logs (last 10 lines):"
    docker-compose logs --tail=10 agent_coordinator
    docker-compose logs --tail=10 agent_worker
    
    # Check if metrics endpoint is accessible
    if docker-compose ps agent_coordinator | grep -q "Up"; then
        print_status "Checking agent metrics endpoint..."
        if curl -f http://localhost:9091/health >/dev/null 2>&1; then
            print_status "Agent metrics endpoint is accessible"
        else
            print_warning "Agent metrics endpoint is not accessible"
        fi
    fi
}

# Function to scale agents
scale_agents() {
    print_header "Scaling agents"
    
    read -p "Enter number of worker replicas: " replicas
    
    cd "$PROJECT_ROOT"
    
    print_status "Scaling agent workers to $replicas replicas..."
    docker-compose up -d --scale agent_worker=$replicas
    
    print_status "Agent scaling completed"
    check_agent_status
}

# Function to view agent logs
view_agent_logs() {
    print_header "Viewing agent logs"
    
    cd "$PROJECT_ROOT"
    
    print_status "Agent coordinator logs:"
    docker-compose logs -f agent_coordinator &
    COORDINATOR_PID=$!
    
    print_status "Agent worker logs:"
    docker-compose logs -f agent_worker &
    WORKER_PID=$!
    
    print_status "Press Ctrl+C to stop viewing logs"
    
    # Wait for user to stop
    trap "kill $COORDINATOR_PID $WORKER_PID 2>/dev/null; exit" INT
    wait
}

# Function to show help
show_help() {
    echo "Background Agent Configuration Script for Bug Hunting Framework"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup           - Initial setup of agent configuration"
    echo "  configure       - Interactive configuration of all agent settings"
    echo "  start           - Start background agents"
    echo "  stop            - Stop background agents"
    echo "  restart         - Restart background agents"
    echo "  status          - Check agent status"
    echo "  scale           - Scale agent workers"
    echo "  logs            - View agent logs"
    echo "  help            - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup        # Initial setup"
    echo "  $0 configure    # Configure all settings"
    echo "  $0 start        # Start agents"
    echo "  $0 status       # Check status"
}

# Main script logic
main() {
    print_header "Bug Hunting Framework - Background Agent Configuration"
    
    # Check prerequisites
    check_docker
    check_docker_compose
    
    # Parse command line arguments
    case "${1:-help}" in
        setup)
            setup_env_file
            print_status "Setup completed successfully"
            ;;
        configure)
            setup_env_file
            configure_agent_scaling
            configure_agent_performance
            configure_agent_monitoring
            configure_agent_security
            print_status "Configuration completed successfully"
            ;;
        start)
            start_agents
            ;;
        stop)
            stop_agents
            ;;
        restart)
            restart_agents
            ;;
        status)
            check_agent_status
            ;;
        scale)
            scale_agents
            ;;
        logs)
            view_agent_logs
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 