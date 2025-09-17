#!/bin/bash
# Fast Docker build script with progress indicators and optimization tips

echo "🚀 Building AutoVulRepair Docker Container"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check for existing image
if docker images | grep -q "autovulrepair"; then
    echo "📦 Existing AutoVulRepair image found."
    read -p "Do you want to rebuild? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "✅ Using existing image."
        exit 0
    fi
fi

echo "⏱️  Expected build time: 5-8 minutes (first time)"
echo "📥 Will download ~350MB of dependencies"
echo ""

# Build with progress
echo "🔨 Starting build..."
start_time=$(date +%s)

docker build -t autovulrepair:latest . --progress=plain

build_exit_code=$?
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "=========================================="
if [ $build_exit_code -eq 0 ]; then
    echo "✅ Build completed successfully!"
    echo "⏱️  Total time: ${duration} seconds"
    echo ""
    echo "🎯 Next steps:"
    echo "   ./test_module1.sh     # Run full test"
    echo "   or"
    echo "   docker run --rm -v \$(pwd)/artifacts:/app/artifacts -v \$(pwd)/src:/app/src autovulrepair:latest /app/pipeline/static_scan.sh /app/src"
else
    echo "❌ Build failed after ${duration} seconds"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   - Check internet connection"
    echo "   - Ensure Docker has enough disk space (2GB+)"
    echo "   - Try: docker system prune -f"
    exit 1
fi
