package advancedscan

import (
	"fmt"
	"strings"

	advancedpb "go-server/gen/advanced"
	redisutil "go-server/redis"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const maxAdvancedChainSteps = 4

func validateAdvancedStepCount(stepCount int) error {
	if stepCount <= 0 {
		return fmt.Errorf("at least one tool is required")
	}
	if stepCount > maxAdvancedChainSteps {
		return fmt.Errorf("advanced mode supports at most %d tools per job, got %d", maxAdvancedChainSteps, stepCount)
	}
	return nil
}

func marshalQueuedProtoMessage(message proto.Message) (string, error) {
	if message == nil {
		return "", nil
	}

	body, err := protojson.Marshal(message)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func buildQueuedExecutionRequest(payload *redisutil.ScanJobPayload) (*advancedpb.SubmitScanRequest, error) {
	request := &advancedpb.SubmitScanRequest{
		ProjectId:   payload.ProjectID,
		TargetValue: payload.TargetValue,
	}

	if strings.TrimSpace(payload.ExecutionConfigJSON) != "" {
		request.ExecutionConfig = &advancedpb.ExecutionConfig{}
		if err := protojson.Unmarshal([]byte(payload.ExecutionConfigJSON), request.ExecutionConfig); err != nil {
			return nil, fmt.Errorf("decode execution_config: %w", err)
		}
	}

	if strings.TrimSpace(payload.ShadowConfigJSON) != "" {
		request.ShadowConfig = &advancedpb.ShadowOutputConfig{}
		if err := protojson.Unmarshal([]byte(payload.ShadowConfigJSON), request.ShadowConfig); err != nil {
			return nil, fmt.Errorf("decode shadow_config: %w", err)
		}
	}

	return request, nil
}
