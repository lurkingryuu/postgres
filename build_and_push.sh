#!/bin/bash
# Build and push Cedar PostgreSQL Docker image
# This script builds the modified PostgreSQL with Cedar authorization hooks

set -e  # Exit on any error

# Configuration
REGISTRY="${REGISTRY:-docker.io/lurkingryuu}"
IMAGE_NAME="${IMAGE_NAME:-postgres-cedar}"
TAG="${TAG:-latest}"
FULL_IMAGE_NAME="${REGISTRY}/${IMAGE_NAME}:${TAG}"

echo "Building and pushing Cedar PostgreSQL Docker image"
echo "=================================================="
echo "Registry: ${REGISTRY}"
echo "Image: ${IMAGE_NAME}"
echo "Tag: ${TAG}"
echo "Full image: ${FULL_IMAGE_NAME}"
echo ""

# Check if we're in the right directory
if [ ! -f "postgres-cedar.Dockerfile" ]; then
    echo "Error: postgres-cedar.Dockerfile not found in current directory"
    echo "Please run this script from the postgres directory"
    exit 1
fi

# Check if required files exist
REQUIRED_FILES=(
    "postgres-cedar.Dockerfile"
    "postgres-init.sql"
    "cedar_auth.control"
    "cedar_auth--1.0.sql"
)

echo "Checking required files..."
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file '$file' not found"
        exit 1
    else
        echo "✓ Found $file"
    fi
done
echo ""

# Build the Docker image (with progress output and BuildKit)
echo "Building Docker image..."
echo "Command: DOCKER_BUILDKIT=1 docker build --load -f postgres-cedar.Dockerfile -t ${FULL_IMAGE_NAME} ."
echo "Note: This build can take 10-15 minutes. If it gets stuck, try Ctrl+C and run again."
echo "Tip: Docker BuildKit enabled for faster builds. Fixed UUID library dependency issue."
DOCKER_BUILDKIT=1 docker build --load -f postgres-cedar.Dockerfile -t "${FULL_IMAGE_NAME}" .

if [ $? -eq 0 ]; then
    echo "✓ Docker image built successfully: ${FULL_IMAGE_NAME}"
else
    echo "✗ Docker build failed"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "Run './troubleshoot_build.sh' for diagnostics"
    echo "Or try: docker system prune -f && ./build_and_push.sh"
    exit 1
fi
echo ""

# Test the image (optional)
if [ "${SKIP_TEST:-false}" != "true" ]; then
    echo "Testing Docker image..."
    if docker run --rm "${FULL_IMAGE_NAME}" --version &>/dev/null; then
        echo "✓ Docker image test passed"
    else
        echo "⚠️  Docker image test failed, but continuing with push"
    fi
    echo ""
fi

# Push the image
echo "Pushing Docker image to registry..."
echo "Command: docker push ${FULL_IMAGE_NAME}"
docker push "${FULL_IMAGE_NAME}"

if [ $? -eq 0 ]; then
    echo "✓ Docker image pushed successfully: ${FULL_IMAGE_NAME}"
else
    echo "✗ Docker push failed"
    exit 1
fi
echo ""

# Success message
echo "🎉 Build and push completed successfully!"
echo ""
echo "Next steps:"
echo "1. Set the environment variable in your experiments:"
echo "   export POSTGRES_CEDAR_IMAGE=${FULL_IMAGE_NAME}"
echo ""
echo "2. Start the PostgreSQL services:"
echo "   cd /path/to/experiments"
echo "   docker-compose up postgres-baseline postgres-cedar -d"
echo ""
echo "3. Run benchmarks:"
echo "   make e8-pgbench-baseline"
echo "   make e8-pgbench-cedar"
echo "   make e8-pgbench-compare"
