package basicscan

import (
	"context"
	"fmt"

	basicpb "go-server/gen/basic"
)

const (
	maxBasicToolArgsCount    = 128
	maxBasicCustomFlagsCount = 128
)

func (s *basicScanServer) SubmitScan(ctx context.Context, req *basicpb.SubmitScanRequest) (*basicpb.SubmitScanResponse, error) {
	basicReq, err := buildBasicSubmitRequest(req)
	if err != nil {
		logValidationFailure("submit", err)
		return nil, err
	}

	return s.submitToDelegate(ctx, basicReq)
}

func buildBasicSubmitRequest(req *basicpb.SubmitScanRequest) (*basicpb.SubmitScanRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	if err := validateBasicSubmitRequest(req); err != nil {
		return nil, err
	}
	if len(req.GetToolArgs()) > maxBasicToolArgsCount {
		return nil, fmt.Errorf("tool_args exceeds max allowed entries (%d)", maxBasicToolArgsCount)
	}
	if len(req.GetCustomFlags()) > maxBasicCustomFlagsCount {
		return nil, fmt.Errorf("custom_flags exceeds max allowed entries (%d)", maxBasicCustomFlagsCount)
	}

	normalizedToolArgs, err := normalizeToolArgs(req.GetToolArgs())
	if err != nil {
		return nil, err
	}
	customFlags, err := parseCustomFlags(req.GetCustomFlags())
	if err != nil {
		return nil, err
	}

	return &basicpb.SubmitScanRequest{
		ProjectId:      stringsTrim(req.GetProjectId()),
		TargetId:       stringsTrim(req.GetTargetId()),
		Target:         stringsTrim(req.GetTarget()),
		IdempotencyKey: normalizeIdempotencyKey(req.GetIdempotencyKey()),
		ToolName:       stringsTrim(req.GetToolName()),
		ToolArgs:       normalizedToolArgs,
		CustomFlags:    customFlags,
	}, nil
}

func validateBasicSubmitRequest(req *basicpb.SubmitScanRequest) error {
	if stringsTrim(req.GetToolName()) == "" {
		return fmt.Errorf("tool_name is required")
	}
	if stringsTrim(req.GetProjectId()) == "" {
		return fmt.Errorf("project_id is required")
	}
	if stringsTrim(req.GetTarget()) == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

func normalizeIdempotencyKey(v string) string {
	return stringsTrim(v)
}
