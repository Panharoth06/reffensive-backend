#!/bin/bash

# setup-gvisor.sh - Install and configure gVisor runtime for Docker
# This script installs gVisor (runsc) and configures Docker to use it

set -e

echo "=== gVisor Setup Script ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"

# Install gVisor based on OS
case $OS in
    ubuntu|debian)
        echo "Installing gVisor for Debian/Ubuntu..."
        
        # Install prerequisites
        apt-get update
        apt-get install -y curl gnupg
        
        # Add gVisor repository
        curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
        
        apt-get update
        apt-get install -y runsc
        ;;
    
    centos|rhel|fedora)
        echo "Installing gVisor for RHEL/CentOS/Fedora..."
        
        # Add gVisor repository
        cat > /etc/yum.repos.d/gvisor.repo << EOF
[gvisor]
name=gvisor
baseurl=https://storage.googleapis.com/gvisor/releases/release/main/$(uname -m)
enabled=1
repo_gpgcheck=1
gpgkey=https://gvisor.dev/archive.key
EOF
        
        yum install -y runsc
        ;;
    
    *)
        echo "Unsupported OS: $OS"
        echo "Please install gVisor manually: https://gvisor.dev/docs/user_guide/install/"
        exit 1
        ;;
esac

# Verify runsc installation
echo ""
echo "Verifying runsc installation..."
if ! command -v runsc &> /dev/null; then
    echo "ERROR: runsc not found in PATH"
    exit 1
fi

RUNSC_VERSION=$(runsc --version 2>&1 | head -n 1)
echo "✓ runsc installed: $RUNSC_VERSION"

# Configure Docker daemon
echo ""
echo "Configuring Docker daemon..."

DOCKER_CONFIG="/etc/docker/daemon.json"

# Create backup if exists
if [ -f "$DOCKER_CONFIG" ]; then
    cp "$DOCKER_CONFIG" "${DOCKER_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    echo "✓ Backed up existing daemon.json"
fi

# Create or update daemon.json
if [ -f "$DOCKER_CONFIG" ]; then
    # Check if runsc runtime already configured
    if grep -q "runsc" "$DOCKER_CONFIG"; then
        echo "✓ runsc runtime already configured in daemon.json"
    else
        # Add runsc runtime to existing config
        # Remove trailing brace, add runtime config, close brace
        sed -i 's/}[[:space:]]*$//' "$DOCKER_CONFIG"
        # Add comma if file is not empty and doesn't end with {
        if [ -s "$DOCKER_CONFIG" ] && ! tail -c 2 "$DOCKER_CONFIG" | grep -q '{$'; then
            echo "," >> "$DOCKER_CONFIG"
        fi
        cat >> "$DOCKER_CONFIG" << EOF
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
EOF
        echo "✓ Added runsc runtime to daemon.json"
    fi
else
    # Create new daemon.json
    cat > "$DOCKER_CONFIG" << EOF
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
EOF
    echo "✓ Created daemon.json with runsc runtime"
fi

# Restart Docker
echo ""
echo "Restarting Docker service..."
systemctl restart docker

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to restart Docker"
    exit 1
fi

# Verify Docker runtime
echo ""
echo "Verifying Docker runtime configuration..."
if docker info 2>/dev/null | grep -q "runsc"; then
    echo "✓ runsc runtime is available in Docker"
else
    echo "WARNING: runsc not found in Docker info"
    echo "You may need to manually configure Docker or restart the system"
fi

# Test gVisor
echo ""
echo "Testing gVisor with a simple container..."
if docker run --runtime=runsc --rm hello-world &> /dev/null; then
    echo "✓ gVisor is working correctly"
else
    echo "Pulling hello-world and testing..."
    docker pull hello-world > /dev/null 2>&1
    if docker run --runtime=runsc --rm hello-world &> /dev/null; then
        echo "✓ gVisor is working correctly"
    else
        echo "WARNING: Test container failed"
        echo "You can still try running the docker runner, but gVisor may have issues"
    fi
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To verify gVisor is available:"
echo "  docker info | grep runsc"
echo ""
echo "To use gVisor in your Docker containers:"
echo "  docker run --runtime=runsc <image> <command>"
echo ""
echo "Or in docker-compose.yml:"
echo "  services:"
echo "    your-service:"
echo "      runtime: runsc"
echo ""
