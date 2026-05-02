# Docker Runner with gVisor - Quick Start Guide

## Overview

This Docker runner allows you to execute security tools in isolated containers with **gVisor** security sandboxing. gVisor provides an additional layer of security by running containers in a user-space kernel, reducing the attack surface.

## Installation

### Step 1: Install gVisor

Run the setup script (requires sudo):

```bash
cd go-server/docker
sudo ./setup-gvisor.sh
```

Or install manually:

```bash
# Ubuntu/Debian
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# Configure Docker
sudo cat >> /etc/docker/daemon.json << EOF
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
EOF

sudo systemctl restart docker
```

### Step 2: Verify Installation

```bash
# Check runsc is installed
runsc --version

# Check Docker recognizes runsc
docker info | grep runsc

# Test with hello-world
docker run --runtime=runsc --rm hello-world
```

## Usage Examples

### Example 1: Run Subfinder (Subdomain Enumeration)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "go-server/docker"
)

func main() {
    ctx := context.Background()
    
    // Simple usage
    result, err := docker.RunToolSimple(
        ctx,
        "projectdiscovery/subfinder:latest",
        "subfinder",
        "-d", "example.com",
        "-silent",
    )
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Subdomains:\n%s\n", result.Stdout)
}
```

### Example 2: Run with Volume Mounts

```go
runner, err := docker.NewRunner()
if err != nil {
    log.Fatal(err)
}

config := docker.ToolConfig{
    Image:   "projectdiscovery/nuclei:latest",
    Command: "nuclei",
    Args: []string{
        "-u", "https://example.com",
        "-t", "/templates/vulnerabilities/",
        "-silent",
    },
    Volumes: []string{
        "/home/user/nuclei-templates:/templates",
    },
    UseGVisor: true,
    Timeout:   15 * time.Minute,
}

result, err := runner.Run(ctx, config)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Vulnerabilities:\n%s\n", result.Stdout)
```

### Example 3: Run with Resource Limits

```go
config := docker.ToolConfig{
    Image:     "projectdiscovery/httpx:latest",
    Command:   "httpx",
    Args:      []string{"-u", "https://example.com", "-silent"},
    UseGVisor: true,
    Timeout:   5 * time.Minute,
    
    // Resource limits
    MemoryLimit: 256 * 1024 * 1024, // 256 MB
    CPUQuota:    50000,             // 50% CPU
}

result, err := runner.Run(ctx, config)
```

### Example 4: Check gVisor Availability

```go
if docker.IsGVisorAvailable() {
    fmt.Println("gVisor is available - running with sandbox")
} else {
    fmt.Println("gVisor not available - running without sandbox")
}
```

## Common Security Tools

### Subfinder (Subdomain Enumeration)
```go
config := docker.ToolConfig{
    Image:     "projectdiscovery/subfinder:latest",
    Command:   "subfinder",
    Args:      []string{"-d", "target.com", "-silent"},
    UseGVisor: true,
    Timeout:   5 * time.Minute,
}
```

### Nuclei (Vulnerability Scanner)
```go
config := docker.ToolConfig{
    Image:   "projectdiscovery/nuclei:latest",
    Command: "nuclei",
    Args:    []string{"-u", "https://target.com", "-silent"},
    Volumes: []string{"/path/to/templates:/templates"},
    UseGVisor: true,
    Timeout:   15 * time.Minute,
}
```

### HTTPX (HTTP Probe Tool)
```go
config := docker.ToolConfig{
    Image:     "projectdiscovery/httpx:latest",
    Command:   "httpx",
    Args:      []string{"-u", "https://target.com", "-silent", "-status-code"},
    UseGVisor: true,
    Timeout:   5 * time.Minute,
}
```

### Naabu (Port Scanner)
```go
config := docker.ToolConfig{
    Image:       "projectdiscovery/naabu:latest",
    Command:     "naabu",
    Args:        []string{"-host", "target.com", "-ports", "80,443,8080"},
    NetworkMode: "host",  // Required for SYN scan
    UseGVisor:   false,   // May not work with gVisor (needs raw sockets)
    Timeout:     10 * time.Minute,
}
```

## Configuration Options

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Image` | string | Docker image | `"projectdiscovery/subfinder:latest"` |
| `Command` | string | Command to run | `"subfinder"` |
| `Args` | []string | Command arguments | `[]string{"-d", "example.com"}` |
| `Env` | []string | Environment variables | `[]string{"RATE_LIMIT=100"}` |
| `Volumes` | []string | Volume mounts | `[]string{"/host:/container"}` |
| `WorkDir` | string | Working directory | `"/app"` |
| `Timeout` | time.Duration | Execution timeout | `5 * time.Minute` |
| `UseGVisor` | bool | Enable gVisor | `true` |
| `NetworkMode` | string | Network mode | `"host"`, `"bridge"` |
| `MemoryLimit` | int64 | Memory limit (bytes) | `512 * 1024 * 1024` |
| `CPUQuota` | int64 | CPU quota (microseconds) | `50000` |

## Result Structure

```go
type ToolResult struct {
    Stdout   string        // Standard output
    Stderr   string        // Standard error
    ExitCode int           // Exit code (0 = success)
    Duration time.Duration // Execution time
}
```

## Error Handling

```go
result, err := runner.Run(ctx, config)
if err != nil {
    // Check for specific errors
    if strings.Contains(err.Error(), "runsc") {
        // gVisor-specific error
        log.Println("gVisor failed, try with runc")
    }
    if strings.Contains(err.Error(), "timeout") {
        // Timeout error
        log.Println("Tool execution timed out")
    }
    return err
}

// Check exit code
if result.ExitCode != 0 {
    log.Printf("Tool failed: %s", result.Stderr)
}
```

## Security Best Practices

1. **Always use gVisor** when possible for untrusted tools
2. **Set resource limits** to prevent DoS attacks
3. **Use timeouts** to prevent runaway containers
4. **Minimize volume mounts** - only mount what's necessary
5. **Avoid privileged mode** unless absolutely required
6. **Use non-root images** when available

## Troubleshooting

### "runtime: runsc" not found

```bash
# Verify gVisor installation
which runsc

# Check Docker configuration
cat /etc/docker/daemon.json

# Restart Docker
sudo systemctl restart docker
```

### Permission denied on volumes

```bash
# Ensure proper permissions
chmod 755 /path/to/volume
chown $(whoami):$(whoami) /path/to/volume
```

### Container fails with gVisor

Some tools may not be compatible with gVisor (e.g., tools needing raw sockets). Try without gVisor:

```go
config.UseGVisor = false
```

### Out of memory

Increase memory limit or optimize tool parameters:

```go
config.MemoryLimit = 1024 * 1024 * 1024 // 1 GB
```

## Docker Compose Integration

Add to your `docker-compose.yml`:

```yaml
services:
  go-server:
    build: ./go-server
    runtime: runsc  # Enable gVisor
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - USE_GVISOR=true
```

## API Reference

For complete API documentation, see:
- [docker_runner.go](docker_runner.go) - Main implementation
- [docker_runner_example.go](docker_runner_example.go) - Usage examples
- [README.md](README.md) - Full documentation

## Support

For issues or questions:
1. Check the [README.md](README.md) for detailed documentation
2. Review example code in `docker_runner_example.go`
3. Verify gVisor installation with `./setup-gvisor.sh --test`

## License

Part of the auto-offensive-backend project.
