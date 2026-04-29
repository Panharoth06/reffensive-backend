package docker

import (
	"context"
	"fmt"
	"time"
)

// Example usage of the Docker runner with gVisor

func ExampleUsage() {
	ctx := context.Background()

	// Example 1: Run subfinder with gVisor
	exampleSubfinder(ctx)

	// Example 2: Run httpx with gVisor
	exampleHTTPX(ctx)

	// Example 3: Run naabu (port scanner) with gVisor
	exampleNaabu(ctx)

	// Example 4: Run tool with volume mounts
	exampleWithVolume(ctx)

	// Example 5: Run with custom configuration
	exampleCustomConfig(ctx)
}

// exampleSubfinder demonstrates running subfinder for subdomain enumeration
func exampleSubfinder(ctx context.Context) {
	runner, err := NewRunner()
	if err != nil {
		panic(err)
	}

	config := ToolConfig{
		Image:   "projectdiscovery/subfinder:latest",
		Command: "subfinder",
		Args: []string{
			"-d", "example.com",
			"-silent",
		},
		UseGVisor: true,
		Timeout:   5 * time.Minute,
	}

	result, err := runner.Run(ctx, config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Subdomains found:\n%s", result.Stdout)
	if result.Stderr != "" {
		fmt.Printf("Errors: %s\n", result.Stderr)
	}
	fmt.Printf("Execution time: %v\n", result.Duration)
}

// exampleHTTPX demonstrates running httpx for HTTP probing
func exampleHTTPX(ctx context.Context) {
	result, err := RunToolSimple(
		ctx,
		"projectdiscovery/httpx:latest",
		"httpx",
		"-u", "https://example.com",
		"-silent",
		"-status-code",
		"-title",
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("HTTP Response:\n%s", result.Stdout)
}

// exampleNaabu demonstrates running naabu for port scanning
func exampleNaabu(ctx context.Context) {
	runner, err := NewRunner()
	if err != nil {
		panic(err)
	}

	config := ToolConfig{
		Image:   "projectdiscovery/naabu:latest",
		Command: "naabu",
		Args: []string{
			"-host", "example.com",
			"-ports", "80,443,8080",
			"-silent",
		},
		UseGVisor:   true,
		Timeout:     10 * time.Minute,
		NetworkMode: "host", // Required for SYN scan
	}

	result, err := runner.Run(ctx, config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Open ports:\n%s", result.Stdout)
}

// exampleWithVolume demonstrates running a tool with volume mounts
func exampleWithVolume(ctx context.Context) {
	runner, err := NewRunner()
	if err != nil {
		panic(err)
	}

	config := ToolConfig{
		Image:   "projectdiscovery/nuclei:latest",
		Command: "nuclei",
		Args: []string{
			"-u", "https://example.com",
			"-t", "/templates/exposures/",
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
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Vulnerabilities found:\n%s", result.Stdout)
}

// exampleCustomConfig demonstrates running with custom resource limits
func exampleCustomConfig(ctx context.Context) {
	runner, err := NewRunner()
	if err != nil {
		panic(err)
	}

	config := ToolConfig{
		Image:   "projectdiscovery/subfinder:latest",
		Command: "subfinder",
		Args: []string{
			"-d", "example.com",
			"-t", "50", // 50 threads
		},
		UseGVisor:   true,
		Timeout:     5 * time.Minute,
		MemoryLimit: 512 * 1024 * 1024, // 512 MB
		CPUQuota:    50000,             // 50% CPU
		Env: []string{
			"SUBFINDER_RATE_LIMIT=100",
		},
	}

	result, err := runner.Run(ctx, config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Result: %s\n", result.Stdout)
}

// Example integration with your existing tool system
func RunSecurityTool(ctx context.Context, toolConfig ToolConfig) (*ToolResult, error) {
	// Ensure gVisor is used by default for security
	if toolConfig.UseGVisor {
		if !IsGVisorAvailable() {
			fmt.Println("Warning: gVisor not available, running without sandbox")
			toolConfig.UseGVisor = false
		}
	} else {
		fmt.Println("Warning: Running without gVisor sandbox")
	}

	runner, err := NewRunner()
	if err != nil {
		return nil, err
	}

	return runner.Run(ctx, toolConfig)
}
