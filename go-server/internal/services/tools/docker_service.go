package services

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// DockerService provides Docker image operations for tool management.
type DockerService struct {
	client *client.Client
}

// NewDockerService creates a new Docker service connected to the local Docker daemon.
func NewDockerService() (*DockerService, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	return &DockerService{client: cli}, nil
}

// PullImage pulls a Docker image from a registry (e.g., Docker Hub).
// imageRef examples: "python:3.11-slim", "docker.io/library/python:3.11-slim"
func (s *DockerService) PullImage(ctx context.Context, imageRef string) error {
	reader, err := s.client.ImagePull(ctx, imageRef, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageRef, err)
	}
	defer reader.Close()

	// Read the pull progress output (discard for now, can be logged if needed)
	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return fmt.Errorf("failed to read pull progress: %w", err)
	}

	return nil
}

// ImageExists checks if an image exists locally.
func (s *DockerService) ImageExists(ctx context.Context, imageRef string) (bool, error) {
	_, err := s.client.ImageInspect(ctx, imageRef)
	if err != nil {
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// PullImageIfNotExists pulls an image only if it doesn't exist locally.
func (s *DockerService) PullImageIfNotExists(ctx context.Context, imageRef string) error {
	exists, err := s.ImageExists(ctx, imageRef)
	if err != nil {
		return err
	}

	if !exists {
		return s.PullImage(ctx, imageRef)
	}

	return nil
}
