package mediumscan

import (
	"context"
	"net"
	"strings"

	db "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *mediumScanServer) resolveTool(ctx context.Context, toolIDText, toolName string) (db.Tool, error) {
	toolName = stringsTrim(toolName)
	toolIDText = stringsTrim(toolIDText)

	switch {
	case toolName != "":
		toolRow, err := s.queries.GetToolByName(ctx, toolName)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.NotFound, "tool_name %q not found: %v", toolName, err)
		}
		if toolIDText == "" {
			return toolRow, nil
		}
		toolID, err := uuid.Parse(toolIDText)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
		}
		if toolRow.ToolID != toolID {
			return db.Tool{}, status.Error(codes.InvalidArgument, "tool_name and tool_id refer to different tools")
		}
		return toolRow, nil
	case toolIDText != "":
		toolID, err := uuid.Parse(toolIDText)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.InvalidArgument, "invalid tool_id: %v", err)
		}
		toolRow, err := s.queries.GetToolByID(ctx, toolID)
		if err != nil {
			return db.Tool{}, status.Errorf(codes.NotFound, "tool_id %q not found: %v", toolIDText, err)
		}
		return toolRow, nil
	default:
		return db.Tool{}, status.Error(codes.InvalidArgument, "tool_name is required")
	}
}

func (s *mediumScanServer) resolveOrCreateTargetForProject(ctx context.Context, projectUUID uuid.UUID, targetIDText, targetValue string) (uuid.UUID, db.Target, error) {
	targetIDText = stringsTrim(targetIDText)
	targetValue = stringsTrim(targetValue)
	if targetValue == "" && targetIDText != "" {
		if _, err := uuid.Parse(targetIDText); err != nil {
			targetValue = targetIDText
			targetIDText = ""
		}
	}
	if targetIDText != "" {
		targetUUID, err := uuid.Parse(targetIDText)
		if err != nil {
			return uuid.Nil, db.Target{}, status.Errorf(codes.InvalidArgument, "invalid target_id: %v", err)
		}
		targetRow, err := s.queries.GetTargetByID(ctx, targetUUID)
		if err != nil {
			return uuid.Nil, db.Target{}, status.Errorf(codes.NotFound, "target_id %q not found: %v", targetIDText, err)
		}
		if targetRow.ProjectID != projectUUID {
			return uuid.Nil, db.Target{}, status.Error(codes.InvalidArgument, "target_id does not belong to project_id")
		}
		return targetUUID, targetRow, nil
	}
	if targetValue == "" {
		return uuid.Nil, db.Target{}, status.Error(codes.InvalidArgument, "target_value is required")
	}

	targets, err := s.queries.ListTargetsByProject(ctx, projectUUID)
	if err != nil {
		return uuid.Nil, db.Target{}, status.Errorf(codes.Internal, "failed to list targets: %v", err)
	}
	incomingCmp := comparableTargetValue(targetValue)
	for _, existing := range targets {
		if comparableTargetValue(existing.Name) == incomingCmp {
			return existing.TargetID, existing, nil
		}
	}

	created, err := s.queries.CreateTarget(ctx, db.CreateTargetParams{
		ProjectID: projectUUID,
		Name:      targetValue,
		Type:      inferTargetType(targetValue),
		Description: pgtype.Text{
			Valid: false,
		},
	})
	if err != nil {
		return uuid.Nil, db.Target{}, status.Errorf(codes.Internal, "failed to create target: %v", err)
	}
	return created.TargetID, created, nil
}

func comparableTargetValue(v string) string {
	trimmed := stringsTrim(v)
	trimmed = strings.TrimRight(trimmed, "/")
	return strings.ToLower(trimmed)
}

func inferTargetType(v string) string {
	trimmed := stringsTrim(v)
	if trimmed == "" {
		return "domain"
	}
	if strings.Contains(trimmed, "://") {
		return "url"
	}
	if _, _, err := net.ParseCIDR(trimmed); err == nil {
		return "cidr"
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return "ip"
	}
	return "domain"
}
