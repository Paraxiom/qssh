#!/bin/bash
set -e

# QSSH Docker Run Script
# Convenient script to run QSSH containers

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
MODE="server"
TAG="qssh:latest"
PORT="22222"
VERBOSE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE="-v"
            shift
            ;;
        --help|-h)
            echo "QSSH Docker Run Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --mode MODE      Run mode: server, client, or compose (default: server)"
            echo "  --tag TAG        Docker image tag (default: qssh:latest)"
            echo "  --port PORT      Host port to bind (default: 22222)"
            echo "  --verbose, -v    Verbose output"
            echo "  --help, -h       Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                           # Start server on port 22222"
            echo "  $0 --mode compose            # Start with docker-compose"
            echo "  $0 --mode client --verbose   # Start client container with verbose output"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}🔐 QSSH - Quantum Secure Shell${NC}"
echo -e "${BLUE}Running in ${MODE} mode${NC}"

case $MODE in
    server)
        echo -e "${YELLOW}Starting QSSH server on port ${PORT}...${NC}"
        docker run -it --rm \
            -p "${PORT}:22222" \
            -v "qssh_keys:/home/qssh/.qssh" \
            -v "qssh_logs:/var/log/qssh" \
            --name qsshd-server \
            $VERBOSE \
            "$TAG"
        ;;

    client)
        echo -e "${YELLOW}Starting QSSH client container...${NC}"
        docker run -it --rm \
            -v "qssh_client_keys:/home/qssh/.qssh" \
            --network "qssh_qssh_network" \
            --name qssh-client \
            --entrypoint /bin/bash \
            "$TAG"
        ;;

    compose)
        echo -e "${YELLOW}Starting with docker-compose...${NC}"
        if [ ! -f "docker-compose.yml" ]; then
            echo -e "${RED}Error: docker-compose.yml not found${NC}"
            exit 1
        fi

        echo "Available profiles:"
        echo "  Default: qsshd server only"
        echo "  --profile client: Include client container"
        echo "  --profile qkd: Include QKD simulator"
        echo ""

        read -p "Enter docker-compose command (or press Enter for default): " COMPOSE_CMD

        if [ -z "$COMPOSE_CMD" ]; then
            docker-compose up qsshd
        else
            eval "docker-compose $COMPOSE_CMD"
        fi
        ;;

    *)
        echo -e "${RED}Error: Unknown mode '$MODE'${NC}"
        echo "Valid modes: server, client, compose"
        exit 1
        ;;
esac