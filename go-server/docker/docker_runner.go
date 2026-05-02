package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

type ContainerFile struct {
	Path    string `json:"path"`
	Content []byte `json:"-"`
	Mode    int64  `json:"mode,omitempty"`
}

type ImagePullPolicy string

const (
	ImagePullIfMissing ImagePullPolicy = "if_missing"
	ImagePullNever     ImagePullPolicy = "never"
)

// ToolConfig defines the configuration for running a security tool in Docker
type ToolConfig struct {
	// Image is the Docker image to use (e.g., "projectdiscovery/subfinder:latest")
	Image string `json:"image"`
	// Command is the base command to run (e.g., "subfinder")
	Command string `json:"command"`
	// Args are the arguments to pass to the command
	Args []string `json:"args,omitempty"`
	// Env are environment variables to set in the container
	Env []string `json:"env,omitempty"`
	// Volumes are volume mounts (host:container)
	Volumes []string `json:"volumes,omitempty"`
	// Files are copied into the container before execution starts.
	Files []ContainerFile `json:"-"`
	// WorkDir is the working directory inside the container
	WorkDir string `json:"work_dir,omitempty"`
	// ImagePullPolicy controls whether the runner may pull the image when missing.
	ImagePullPolicy ImagePullPolicy `json:"image_pull_policy,omitempty"`
	// Timeout is the maximum execution time
	Timeout time.Duration `json:"timeout,omitempty"`
	// UseGVisor enables gVisor runtime (runsc)
	UseGVisor bool `json:"use_gvisor,omitempty"`
	// NetworkMode sets the container network mode
	NetworkMode string `json:"network_mode,omitempty"`
	// Privileged runs the container in privileged mode (not recommended with gVisor)
	Privileged bool `json:"privileged,omitempty"`
	// CapAdd is a narrow allowlist of Linux capabilities granted to the container.
	CapAdd []string `json:"cap_add,omitempty"`
	// MemoryLimit limits container memory (e.g., "512m")
	MemoryLimit int64 `json:"memory_limit,omitempty"`
	// CPUQuota limits CPU usage
	CPUQuota int64 `json:"cpu_quota,omitempty"`
	// OnLog is called for each line emitted by stdout/stderr.
	// source is either "stdout" or "stderr".
	OnLog func(source, line string) `json:"-"`
}

// ToolResult contains the execution result
type ToolResult struct {
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

// Runner handles Docker container execution with gVisor support
type Runner struct {
	client *client.Client
}

// NewRunner creates a new Docker runner
func NewRunner() (*Runner, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &Runner{client: cli}, nil
}

// Run executes a tool in a Docker container with gVisor security
func (r *Runner) Run(ctx context.Context, config ToolConfig) (*ToolResult, error) {
	startTime := time.Now()

	if err := validateExecutionPolicy(config); err != nil {
		return nil, err
	}

	// Create context with timeout if specified
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	// Pull image if not present
	if err := r.ensureImage(ctx, config.Image, config.ImagePullPolicy); err != nil {
		return nil, fmt.Errorf("failed to ensure image: %w", err)
	}

	// Build container configuration
	containerConfig := &container.Config{
		Image:      config.Image,
		Env:        config.Env,
		Entrypoint: []string{config.Command},
		Cmd:        config.Args,
	}

	// Set working directory
	if config.WorkDir != "" {
		containerConfig.WorkingDir = config.WorkDir
	}

	// Build host configuration
	hostConfig := &container.HostConfig{
		Privileged: config.Privileged,
		CapDrop:    []string{"ALL"},
		CapAdd:     append([]string(nil), config.CapAdd...),
	}

	// Set gVisor runtime
	if config.UseGVisor {
		hostConfig.Runtime = "runsc"
	}

	// Set network mode
	if config.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(config.NetworkMode)
	}

	// Set resource limits
	if config.MemoryLimit > 0 {
		hostConfig.Memory = config.MemoryLimit
	}
	if config.CPUQuota > 0 {
		hostConfig.CPUQuota = config.CPUQuota
	}

	// Parse volume mounts
	for _, vol := range config.Volumes {
		parts := strings.Split(vol, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid volume format: %s (expected host:container)", vol)
		}
		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: parts[0],
			Target: parts[1],
		})
	}

	// Check if Docker socket mount is needed
	for _, vol := range config.Volumes {
		if strings.Contains(vol, "/var/run/docker.sock") {
			hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: "/var/run/docker.sock",
				Target: "/var/run/docker.sock",
			})
			break
		}
	}

	// Create container
	resp, err := r.client.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}
	defer func() {
		// Clean up container
		removeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.client.ContainerRemove(removeCtx, resp.ID, container.RemoveOptions{Force: true})
	}()

	if len(config.Files) > 0 {
		if err := r.copyFilesToContainer(ctx, resp.ID, config.Files); err != nil {
			return nil, fmt.Errorf("failed to copy files to container: %w", err)
		}
	}

	// Start container
	if err := r.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Stream logs while container is running.
	logs, err := r.client.ContainerLogs(ctx, resp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open container logs: %w", err)
	}
	defer logs.Close()

	type logResult struct {
		stdout string
		stderr string
		err    error
	}
	logCh := make(chan logResult, 1)
	go func() {
		stdout, stderr, err := streamAndCollectLogs(logs, config.OnLog)
		logCh <- logResult{stdout: stdout, stderr: stderr, err: err}
	}()

	// Wait for container to finish
	statusCh, errCh := r.client.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	var exitCode int
	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("failed to wait for container: %w", err)
		}
	case status := <-statusCh:
		exitCode = int(status.StatusCode)
	}

	logRes := <-logCh
	if logRes.err != nil {
		return nil, fmt.Errorf("failed to stream container logs: %w", logRes.err)
	}

	duration := time.Since(startTime)

	return &ToolResult{
		Stdout:   logRes.stdout,
		Stderr:   logRes.stderr,
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

// StreamedCallbacks holds per-line callbacks used by RunStreamed.
// OnStdoutLine is called for every complete line from the container's stdout.
// OnStderrLine is called for every complete line from the container's stderr.
// Either callback may be nil (that stream is silently discarded).
type StreamedCallbacks struct {
	OnStdoutLine func(line string)
	OnStderrLine func(line string)
}

// RunStreamed starts a container identically to Run but, instead of buffering
// stdout/stderr into strings, it delivers each completed line to the provided
// callbacks in real time. The method blocks until the container exits.
// It returns the exit code and any execution error; the caller is responsible
// for accumulating whatever data it needs inside the callbacks.
func (r *Runner) RunStreamed(ctx context.Context, config ToolConfig, cb StreamedCallbacks) (int, error) {
	if err := validateExecutionPolicy(config); err != nil {
		return -1, err
	}

	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	if err := r.ensureImage(ctx, config.Image, config.ImagePullPolicy); err != nil {
		return -1, fmt.Errorf("failed to ensure image: %w", err)
	}

	containerConfig := &container.Config{
		Image:      config.Image,
		Env:        config.Env,
		Entrypoint: []string{config.Command},
		Cmd:        config.Args,
	}
	if config.WorkDir != "" {
		containerConfig.WorkingDir = config.WorkDir
	}

	hostConfig := &container.HostConfig{
		Privileged: config.Privileged,
		CapDrop:    []string{"ALL"},
		CapAdd:     append([]string(nil), config.CapAdd...),
	}
	if config.UseGVisor {
		hostConfig.Runtime = "runsc"
	}
	if config.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(config.NetworkMode)
	}
	if config.MemoryLimit > 0 {
		hostConfig.Memory = config.MemoryLimit
	}
	if config.CPUQuota > 0 {
		hostConfig.CPUQuota = config.CPUQuota
	}
	for _, vol := range config.Volumes {
		parts := strings.Split(vol, ":")
		if len(parts) < 2 {
			return -1, fmt.Errorf("invalid volume format: %s (expected host:container)", vol)
		}
		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: parts[0],
			Target: parts[1],
		})
	}

	resp, err := r.client.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return -1, fmt.Errorf("failed to create container: %w", err)
	}
	defer func() {
		removeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.client.ContainerRemove(removeCtx, resp.ID, container.RemoveOptions{Force: true})
	}()

	if len(config.Files) > 0 {
		if err := r.copyFilesToContainer(ctx, resp.ID, config.Files); err != nil {
			return -1, fmt.Errorf("failed to copy files to container: %w", err)
		}
	}

	if err := r.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return -1, fmt.Errorf("failed to start container: %w", err)
	}

	logs, err := r.client.ContainerLogs(ctx, resp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return -1, fmt.Errorf("failed to open container logs: %w", err)
	}
	defer logs.Close()

	// Stream logs and route to callbacks.
	streamErrCh := make(chan error, 1)
	go func() {
		streamErrCh <- streamAndDispatchLogs(logs, cb.OnStdoutLine, cb.OnStderrLine)
	}()

	// Wait for container to finish.
	statusCh, errCh := r.client.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	var exitCode int
	select {
	case err := <-errCh:
		if err != nil {
			return -1, fmt.Errorf("failed to wait for container: %w", err)
		}
	case status := <-statusCh:
		exitCode = int(status.StatusCode)
	}

	// Wait for the streaming goroutine to drain (container has already exited).
	if streamErr := <-streamErrCh; streamErr != nil {
		return exitCode, fmt.Errorf("failed to stream container logs: %w", streamErr)
	}

	return exitCode, nil
}

// streamAndDispatchLogs reads the Docker multiplexed log stream and calls
// onStdout / onStderr for each completed line. Either callback may be nil.
func streamAndDispatchLogs(logs io.Reader, onStdout, onStderr func(string)) error {
	pending := [2]string{"", ""}    // 0=stdout, 1=stderr
	callbacks := [2]func(string){onStdout, onStderr}

	emit := func(idx int, chunk string) {
		combined := pending[idx] + chunk
		parts := strings.Split(combined, "\n")
		for i := 0; i < len(parts)-1; i++ {
			line := strings.TrimRight(parts[i], "\r")
			if callbacks[idx] != nil && line != "" {
				callbacks[idx](line)
			}
		}
		pending[idx] = parts[len(parts)-1]
	}

	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(logs, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		streamType := header[0]
		length := int(binary.BigEndian.Uint32(header[4:8]))
		if length <= 0 {
			continue
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(logs, payload); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		switch streamType {
		case 1: // stdout
			emit(0, string(payload))
		case 2: // stderr
			emit(1, string(payload))
		}
	}

	// Flush any unterminated trailing line.
	for idx, cb := range callbacks {
		if cb != nil && pending[idx] != "" {
			line := strings.TrimRight(pending[idx], "\r")
			if line != "" {
				cb(line)
			}
		}
	}
	return nil
}

func validateExecutionPolicy(config ToolConfig) error {
	normalizedNetwork := strings.ToLower(strings.TrimSpace(config.NetworkMode))
	if normalizedNetwork == "host" {
		return fmt.Errorf("host network mode is forbidden")
	}
	switch normalizedNetwork {
	case "", "bridge", "none":
	default:
		return fmt.Errorf("unsupported network mode %q", config.NetworkMode)
	}
	if config.Privileged {
		return fmt.Errorf("privileged containers are forbidden")
	}
	for _, capability := range config.CapAdd {
		normalizedCapability := strings.ToUpper(strings.TrimSpace(capability))
		normalizedCapability = strings.TrimPrefix(normalizedCapability, "CAP_")
		switch normalizedCapability {
		case "NET_RAW":
		case "":
			continue
		default:
			return fmt.Errorf("capability %q is forbidden", normalizedCapability)
		}
	}
	for _, vol := range config.Volumes {
		if strings.Contains(vol, "/var/run/docker.sock") {
			return fmt.Errorf("docker socket mounts are forbidden")
		}
	}
	return nil
}

func (r *Runner) copyFilesToContainer(ctx context.Context, containerID string, files []ContainerFile) error {
	archive, err := buildContainerFilesArchive(files)
	if err != nil {
		return err
	}
	return r.client.CopyToContainer(
		ctx,
		containerID,
		"/",
		archive,
		container.CopyToContainerOptions{
			AllowOverwriteDirWithFile: true,
		},
	)
}

func buildContainerFilesArchive(files []ContainerFile) (io.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writtenDirs := make(map[string]struct{})

	var writeDir func(string) error
	writeDir = func(dir string) error {
		if dir == "." || dir == "/" || dir == "" {
			return nil
		}
		if _, ok := writtenDirs[dir]; ok {
			return nil
		}
		parent := path.Dir(dir)
		if parent != dir {
			if err := writeDir(parent); err != nil {
				return err
			}
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     dir + "/",
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		}); err != nil {
			return err
		}
		writtenDirs[dir] = struct{}{}
		return nil
	}

	for _, file := range files {
		cleaned := path.Clean("/" + strings.TrimSpace(file.Path))
		relPath := strings.TrimPrefix(cleaned, "/")
		if relPath == "" || relPath == "." {
			return nil, fmt.Errorf("container file path is required")
		}

		if err := writeDir(path.Dir(relPath)); err != nil {
			return nil, err
		}

		mode := file.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: relPath,
			Mode: mode,
			Size: int64(len(file.Content)),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(file.Content); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

// ensureImage pulls the Docker image if not present locally
func (r *Runner) ensureImage(ctx context.Context, imageName string, policy ImagePullPolicy) error {
	// Check if image exists
	_, _, err := r.client.ImageInspectWithRaw(ctx, imageName)
	if err == nil {
		return nil // Image already exists
	}

	if normalizeImagePullPolicy(policy) == ImagePullNever {
		return fmt.Errorf("image %s is not available locally and pull policy is %q", imageName, ImagePullNever)
	}

	// Pull image
	reader, err := r.client.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageName, err)
	}
	defer reader.Close()

	// Wait for pull to complete
	_, _ = io.Copy(io.Discard, reader)

	return nil
}

func normalizeImagePullPolicy(policy ImagePullPolicy) ImagePullPolicy {
	switch policy {
	case "", ImagePullIfMissing:
		return ImagePullIfMissing
	case ImagePullNever:
		return ImagePullNever
	default:
		return ImagePullIfMissing
	}
}

func streamAndCollectLogs(logs io.Reader, onLog func(source, line string)) (stdout, stderr string, err error) {
	var stdoutBuilder, stderrBuilder strings.Builder
	stdoutPending := ""
	stderrPending := ""

	emitLines := func(source string, chunk string, pending *string) {
		combined := *pending + chunk
		parts := strings.Split(combined, "\n")
		for i := 0; i < len(parts)-1; i++ {
			line := parts[i]
			if onLog != nil {
				onLog(source, line)
			}
		}
		*pending = parts[len(parts)-1]
	}

	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(logs, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return "", "", err
		}

		streamType := header[0]
		length := int(binary.BigEndian.Uint32(header[4:8]))
		if length <= 0 {
			continue
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(logs, payload); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return "", "", err
		}

		text := string(payload)
		switch streamType {
		case 1: // stdout
			stdoutBuilder.WriteString(text)
			emitLines("stdout", text, &stdoutPending)
		case 2: // stderr
			stderrBuilder.WriteString(text)
			emitLines("stderr", text, &stderrPending)
		}
	}

	if onLog != nil {
		if stdoutPending != "" {
			onLog("stdout", stdoutPending)
		}
		if stderrPending != "" {
			onLog("stderr", stderrPending)
		}
	}

	return stdoutBuilder.String(), stderrBuilder.String(), nil
}

// RunToolSimple is a convenience function for running tools with minimal configuration
func RunToolSimple(ctx context.Context, image, command string, args ...string) (*ToolResult, error) {
	runner, err := NewRunner()
	if err != nil {
		return nil, err
	}

	config := ToolConfig{
		Image:     image,
		Command:   command,
		Args:      args,
		UseGVisor: true,
		Timeout:   5 * time.Minute,
	}

	return runner.Run(ctx, config)
}

// RunWithVolume is a convenience function for running tools with volume mounts
func RunWithVolume(ctx context.Context, image, command string, volumes []string, args ...string) (*ToolResult, error) {
	runner, err := NewRunner()
	if err != nil {
		return nil, err
	}

	config := ToolConfig{
		Image:     image,
		Command:   command,
		Args:      args,
		Volumes:   volumes,
		UseGVisor: true,
		Timeout:   5 * time.Minute,
	}

	return runner.Run(ctx, config)
}

// RunCommandWithDockerInDocker runs a tool that needs Docker-in-Docker access
func RunCommandWithDockerInDocker(ctx context.Context, image, command string, args ...string) (*ToolResult, error) {
	runner, err := NewRunner()
	if err != nil {
		return nil, err
	}

	config := ToolConfig{
		Image:   image,
		Command: command,
		Args:    args,
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
		// Note: gVisor may not work with Docker-in-Docker in all cases
		UseGVisor: false,
		Timeout:   10 * time.Minute,
	}

	return runner.Run(ctx, config)
}

// ValidateGVisorRuntime checks if gVisor (runsc) runtime is available
func ValidateGVisorRuntime() error {
	cmd := exec.Command("docker", "info", "-f", "{{.Runtimes}}")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check docker runtimes: %w", err)
	}

	if !strings.Contains(string(output), "runsc") {
		return fmt.Errorf("gVisor runtime (runsc) is not installed")
	}

	return nil
}

// IsGVisorAvailable returns true if gVisor runtime is available
func IsGVisorAvailable() bool {
	return ValidateGVisorRuntime() == nil
}

// MarshalJSON implements json.Marshaler for ToolResult
func (r *ToolResult) MarshalJSON() ([]byte, error) {
	type Alias ToolResult
	return json.Marshal(&struct {
		*Alias
		DurationSeconds float64 `json:"duration_seconds"`
	}{
		Alias:           (*Alias)(r),
		DurationSeconds: r.Duration.Seconds(),
	})
}
