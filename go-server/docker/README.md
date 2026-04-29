# Docker Runner with gVisor Security

This package provides a secure Docker execution environment for running security tools with gVisor sandboxing.

## Features

- **gVisor Support**: Run untrusted security tools in a secure sandbox using gVisor (runsc runtime)
- **Resource Limits**: Control memory and CPU usage per container
- **Volume Mounts**: Mount host directories for tool configurations and outputs
- **Timeout Control**: Set execution timeouts to prevent runaway containers
- **Automatic Cleanup**: Containers are automatically removed after execution
- **Docker-in-Docker**: Support for tools that need Docker socket access

## Prerequisites

### 1. Install gVisor

```bash
# Install gVisor runtime
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc

# Verify installation
docker info | grep runsc
```

### 2. Configure Docker Daemon

Edit `/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  },
  "default-runtime": "runc"
}
```

Restart Docker:
```bash
sudo systemctl restart docker
```

### 3. Install Go Dependencies

```bash
cd go-server
go get github.com/docker/docker/api/types
go get github.com/docker/docker/client
go get github.com/docker/go-connections/nat
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "fmt"
    "time"
    "your-module/go-server/docker"
)

func main() {
    ctx := context.Background()
    
    runner, err := docker.NewRunner()
    if err != nil {
        panic(err)
    }
    
    config := docker.ToolConfig{
        Image:     "projectdiscovery/subfinder:latest",
        Command:   "subfinder",
        Args:      []string{"-d", "example.com", "-silent"},
        UseGVisor: true,
        Timeout:   5 * time.Minute,
    }
    
    result, err := runner.Run(ctx, config)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Output: %s\n", result.Stdout)
}
```

### Quick Helper Functions

```go
// Simple tool execution
result, err := docker.RunToolSimple(ctx, "projectdiscovery/subfinder:latest", "subfinder", "-d", "example.com")

// With volume mounts
result, err := docker.RunWithVolume(ctx, "projectdiscovery/nuclei:latest", "nuclei", 
    []string{"/path/to/templates:/templates"}, "-u", "https://example.com")
```

### Advanced Configuration

```go
config := docker.ToolConfig{
    Image:       "projectdiscovery/naabu:latest",
    Command:     "naabu",
    Args:        []string{"-host", "example.com", "-ports", "80,443"},
    UseGVisor:   true,
    Timeout:     10 * time.Minute,
    NetworkMode: "host",  // Required for SYN scan
    MemoryLimit: 512 * 1024 * 1024,  // 512 MB
    CPUQuota:    50000,              // 50% CPU
    Env: []string{
        "RATE_LIMIT=100",
    },
}
```

## ToolConfig Options

| Field | Type | Description |
|-------|------|-------------|
| `Image` | string | Docker image to use (e.g., `projectdiscovery/subfinder:latest`) |
| `Command` | string | Base command to run inside container |
| `Args` | []string | Arguments to pass to the command |
| `Env` | []string | Environment variables |
| `Volumes` | []string | Volume mounts in `host:container` format |
| `WorkDir` | string | Working directory inside container |
| `Timeout` | time.Duration | Maximum execution time |
| `UseGVisor` | bool | Enable gVisor sandboxing (recommended) |
| `NetworkMode` | string | Docker network mode (`host`, `bridge`, etc.) |
| `Privileged` | bool | Run in privileged mode (not recommended) |
| `MemoryLimit` | int64 | Memory limit in bytes |
| `CPUQuota` | int64 | CPU quota in microseconds |

## Security Considerations

### gVisor Benefits

- **Kernel Isolation**: gVisor provides a user-space kernel that intercepts syscalls
- **Reduced Attack Surface**: Limits container access to host kernel
- **Resource Control**: Fine-grained control over resources

### When NOT to Use gVisor

- Tools requiring Docker-in-Docker (use regular runc runtime)
- Tools requiring privileged network operations
- Tools using specific kernel features not supported by gVisor

### Best Practices

1. **Always use gVisor** for untrusted tools when possible
2. **Set resource limits** to prevent DoS
3. **Use timeouts** to prevent runaway containers
4. **Minimize volume mounts** to reduce attack surface
5. **Avoid privileged mode** unless absolutely necessary

## Example: Running Common Security Tools

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

### Naabu (Port Scanner)

```go
config := docker.ToolConfig{
    Image:       "projectdiscovery/naabu:latest",
    Command:     "naabu",
    Args:        []string{"-host", "target.com", "-ports", "1-1000"},
    NetworkMode: "host",  // Required for SYN scan
    UseGVisor:   false,   // May not work with gVisor due to raw socket needs
    Timeout:     10 * time.Minute,
}
```

## Error Handling

```go
result, err := runner.Run(ctx, config)
if err != nil {
    if strings.Contains(err.Error(), "runsc") {
        // gVisor-specific error
        log.Println("gVisor execution failed, consider using runc")
    }
    return err
}

if result.ExitCode != 0 {
    log.Printf("Tool failed with exit code %d: %s", result.ExitCode, result.Stderr)
}
```

## Testing

Check if gVisor is available:

```go
if docker.IsGVisorAvailable() {
    fmt.Println("gVisor is available")
} else {
    fmt.Println("gVisor not installed or configured")
}
```

## Troubleshooting

### "runtime: runsc" not found

Ensure gVisor is installed and Docker daemon is configured correctly:

```bash
# Check if runsc is installed
which runsc

# Check Docker runtime configuration
docker info | grep -A 5 "Runtimes"
```

### Permission denied on volume mounts

Ensure the container user has access to the mounted directories:

```go
config := docker.ToolConfig{
    // ...
    Volumes: []string{"/path/to/data:/data:rw"},
}
```

### Container fails to start with gVisor

Some tools may not be compatible with gVisor. Try without gVisor:

```go
config.UseGVisor = false
```

## License

This package is part of the auto-offensive-backend project.
