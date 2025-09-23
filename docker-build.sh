#!/bin/bash
set -e

# QSSH Docker Build Script
# Builds Docker images for quantum-secure SSH

echo "🐳 Building QSSH Docker images..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build arguments
BUILD_ARGS=""
CACHE_FROM=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cache)
            BUILD_ARGS="$BUILD_ARGS --no-cache"
            shift
            ;;
        --platform)
            BUILD_ARGS="$BUILD_ARGS --platform $2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--no-cache] [--platform PLATFORM] [--tag TAG]"
            exit 1
            ;;
    esac
done

# Default tag
TAG=${TAG:-"qssh:latest"}

echo -e "${BLUE}Building QSSH with tag: ${TAG}${NC}"

# Check if Dockerfile exists
if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}Error: Dockerfile not found in current directory${NC}"
    exit 1
fi

# Build the image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build $BUILD_ARGS -t "$TAG" .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Docker image built successfully: ${TAG}${NC}"

    # Show image information
    echo -e "${BLUE}Image information:${NC}"
    docker images "$TAG"

    echo ""
    echo -e "${GREEN}🚀 Ready to run!${NC}"
    echo "To start the server:"
    echo "  docker run -p 22222:22222 $TAG"
    echo ""
    echo "To start with docker-compose:"
    echo "  docker-compose up qsshd"
    echo ""
    echo "To start client for testing:"
    echo "  docker-compose --profile client up"

else
    echo -e "${RED}❌ Docker build failed${NC}"
    exit 1
fi