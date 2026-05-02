package advancedscan

import (
	"testing"

	advancedpb "go-server/gen/advanced"
	redisutil "go-server/redis"
)

func TestValidateAdvancedStepCount(t *testing.T) {
	t.Parallel()

	if err := validateAdvancedStepCount(4); err != nil {
		t.Fatalf("expected 4 steps to be accepted, got %v", err)
	}

	err := validateAdvancedStepCount(5)
	if err == nil {
		t.Fatal("expected 5 steps to be rejected")
	}
}

func TestBuildQueuedExecutionRequest_RestoresExecutionContext(t *testing.T) {
	t.Parallel()

	executionConfigJSON, err := marshalQueuedProtoMessage(&advancedpb.ExecutionConfig{
		TimeoutSeconds: 90,
		ResourceLimits: &advancedpb.ResourceLimits{
			MemoryLimitBytes: 512 * 1024 * 1024,
		},
	})
	if err != nil {
		t.Fatalf("marshalQueuedProtoMessage(execution): %v", err)
	}

	shadowConfigJSON, err := marshalQueuedProtoMessage(&advancedpb.ShadowOutputConfig{
		DefaultPath: "/tmp/shadow",
		Filename:    "step.json",
	})
	if err != nil {
		t.Fatalf("marshalQueuedProtoMessage(shadow): %v", err)
	}

	request, err := buildQueuedExecutionRequest(&redisutil.ScanJobPayload{
		ProjectID:           "project-123",
		TargetValue:         "example.com",
		ExecutionConfigJSON: executionConfigJSON,
		ShadowConfigJSON:    shadowConfigJSON,
	})
	if err != nil {
		t.Fatalf("buildQueuedExecutionRequest() error = %v", err)
	}

	if request.GetProjectId() != "project-123" {
		t.Fatalf("unexpected project_id: %q", request.GetProjectId())
	}
	if request.GetTargetValue() != "example.com" {
		t.Fatalf("unexpected target_value: %q", request.GetTargetValue())
	}
	if request.GetExecutionConfig().GetTimeoutSeconds() != 90 {
		t.Fatalf("unexpected timeout_seconds: %d", request.GetExecutionConfig().GetTimeoutSeconds())
	}
	if request.GetExecutionConfig().GetResourceLimits().GetMemoryLimitBytes() != 512*1024*1024 {
		t.Fatalf("unexpected memory_limit_bytes: %d", request.GetExecutionConfig().GetResourceLimits().GetMemoryLimitBytes())
	}
	if request.GetShadowConfig().GetFilename() != "step.json" {
		t.Fatalf("unexpected shadow filename: %q", request.GetShadowConfig().GetFilename())
	}
	if request.GetShadowConfig().GetDefaultPath() != "/tmp/shadow" {
		t.Fatalf("unexpected shadow default_path: %q", request.GetShadowConfig().GetDefaultPath())
	}
}
