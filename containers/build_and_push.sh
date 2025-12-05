#!/bin/bash
# ExaaiAgnt Docker Image Build & Push Script
# Run this on your Linux server (vpnpanel)

set -e

# Configuration
IMAGE_NAME="ghcr.io/hleliofficiel/exaai-sandbox"
VERSION="1.0"

echo "========================================"
echo "ExaaiAgnt Docker Image Builder"
echo "========================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Check if logged in to GitHub Container Registry
echo ""
echo "Step 1: Login to GitHub Container Registry"
echo "You need a GitHub Personal Access Token with 'write:packages' permission"
echo ""
read -p "Enter your GitHub username: " GITHUB_USER
read -sp "Enter your GitHub token: " GITHUB_TOKEN
echo ""

echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USER --password-stdin

echo ""
echo "Step 2: Building Docker image..."
echo "This may take 15-30 minutes..."
echo ""

docker build -t ${IMAGE_NAME}:${VERSION} -f containers/Dockerfile .

echo ""
echo "Step 3: Tagging image as latest..."
docker tag ${IMAGE_NAME}:${VERSION} ${IMAGE_NAME}:latest

echo ""
echo "Step 4: Pushing image to registry..."
docker push ${IMAGE_NAME}:${VERSION}
docker push ${IMAGE_NAME}:latest

echo ""
echo "========================================"
echo "✅ SUCCESS!"
echo "========================================"
echo ""
echo "Image pushed to: ${IMAGE_NAME}:${VERSION}"
echo ""
echo "To use this image:"
echo "  export EXAAI_IMAGE=\"${IMAGE_NAME}:${VERSION}\""
echo "  exaaiagnt --target https://example.com"
echo ""
