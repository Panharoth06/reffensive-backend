package advancedscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	db "go-server/internal/database/sqlc"
)

type preparedShadowOutput struct {
	Enabled          bool
	Format           string
	Parser           string
	Transport        string
	ContainerPath    string
	HostPath         string
	Volumes          []string
	AddedArgs        []string
	FallbackToStdout bool
	ParseTimeout     time.Duration
}

type capturedShadowOutput struct {
	Format             string
	Parser             string
	Transport          string
	HostPath           string
	ContainerPath      string
	Content            []byte
	UsedStdoutFallback bool
}

func prepareShadowOutput(toolRow db.Tool, jobID string, stepID string) (preparedShadowOutput, error) {
	cfg, err := parseShadowOutputConfig(toolRow.ShadowOutputConfig)
	if err != nil {
		return preparedShadowOutput{}, fmt.Errorf("parse shadow_output_config: %w", err)
	}
	if stringsTrim(cfg.PreferredFormat) == "" {
		return preparedShadowOutput{}, nil
	}

	formatName := stringsTrim(cfg.PreferredFormat)
	format, ok := cfg.Formats[formatName]
	if !ok {
		return preparedShadowOutput{}, fmt.Errorf("preferred shadow format %q is not defined", formatName)
	}

	prepared := preparedShadowOutput{
		Enabled:          true,
		Format:           formatName,
		Parser:           strings.ToLower(stringsTrim(format.Parser)),
		Transport:        strings.ToLower(stringsTrim(format.Transport)),
		FallbackToStdout: cfg.FallbackToStdout,
		ParseTimeout:     time.Duration(cfg.ParseTimeoutSeconds) * time.Second,
	}

	for _, flag := range format.EnableFlags {
		trimmed := stringsTrim(flag)
		if trimmed == "" {
			continue
		}
		prepared.AddedArgs = append(prepared.AddedArgs, trimmed)
	}

	if prepared.Transport != "file" {
		return prepared, nil
	}

	pathFlag := stringsTrim(format.PathFlag)
	if pathFlag == "" {
		return preparedShadowOutput{}, fmt.Errorf("shadow format %q requires path_flag for file transport", formatName)
	}

	containerDir := stringsTrim(cfg.DefaultPath)
	if containerDir == "" {
		containerDir = "/tmp/shadow"
	}
	// Shadow output directories are bind-mounted into tool containers. Use a
	// world-writable temp-style mode so non-root tool images can create their
	// report files without requiring privileged execution.
	if err := os.MkdirAll(containerDir, 0o777); err != nil {
		return preparedShadowOutput{}, fmt.Errorf("create shadow output directory: %w", err)
	}
	if err := os.Chmod(containerDir, 0o777); err != nil {
		return preparedShadowOutput{}, fmt.Errorf("chmod shadow output directory: %w", err)
	}

	baseName := renderShadowFilename(cfg.FilenameTemplate, jobID, stepID, toolRow.ToolName)
	ext := normalizeShadowFileExtension(format.FileExtension)
	pathMode := strings.ToLower(stringsTrim(format.PathMode))
	switch pathMode {
	case "", "file":
		filename := baseName + ext
		prepared.HostPath = filepath.Join(containerDir, filename)
		prepared.ContainerPath = filepath.Join(containerDir, filename)
	case "basename":
		prepared.HostPath = filepath.Join(containerDir, baseName)
		prepared.ContainerPath = filepath.Join(containerDir, baseName)
	default:
		return preparedShadowOutput{}, fmt.Errorf("unsupported shadow path_mode %q", format.PathMode)
	}

	prepared.AddedArgs = append(prepared.AddedArgs, pathFlag, prepared.ContainerPath)
	prepared.Volumes = append(prepared.Volumes, fmt.Sprintf("%s:%s", containerDir, containerDir))
	return prepared, nil
}

func captureShadowOutput(prepared preparedShadowOutput, stdout string) (capturedShadowOutput, error) {
	if !prepared.Enabled {
		return capturedShadowOutput{}, nil
	}

	captured := capturedShadowOutput{
		Format:        prepared.Format,
		Parser:        prepared.Parser,
		Transport:     prepared.Transport,
		HostPath:      prepared.HostPath,
		ContainerPath: prepared.ContainerPath,
	}

	if prepared.Transport != "file" {
		if stringsTrim(stdout) == "" {
			return captured, nil
		}
		captured.Content = []byte(stdout)
		return captured, nil
	}

	if prepared.HostPath != "" {
		deadline := time.Now().Add(prepared.ParseTimeout)
		for {
			data, err := os.ReadFile(prepared.HostPath)
			if err == nil {
				captured.Content = data
				return captured, nil
			}
			if !os.IsNotExist(err) {
				return capturedShadowOutput{}, fmt.Errorf("read shadow output file: %w", err)
			}
			if prepared.ParseTimeout <= 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	if prepared.FallbackToStdout && stringsTrim(stdout) != "" {
		captured.Content = []byte(stdout)
		captured.UsedStdoutFallback = true
		return captured, nil
	}

	return captured, nil
}

func renderShadowFilename(template string, jobID string, stepID string, toolName string) string {
	base := stringsTrim(template)
	if base == "" {
		base = "{job_id}_{step_id}_{tool_name}_{timestamp}"
	}
	replacements := map[string]string{
		"{job_id}":    jobID,
		"{step_id}":   stepID,
		"{tool_name}": toolName,
		"{timestamp}": fmt.Sprintf("%d", time.Now().UTC().Unix()),
	}
	for token, value := range replacements {
		base = strings.ReplaceAll(base, token, value)
	}
	if stringsTrim(base) == "" {
		return fmt.Sprintf("%s_%s_%s", jobID, stepID, toolName)
	}
	return base
}

func normalizeShadowFileExtension(ext string) string {
	trimmed := stringsTrim(ext)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, ".") {
		return trimmed
	}
	return "." + trimmed
}
