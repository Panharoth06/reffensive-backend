package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	pb "go-server/gen/sonarqube"
	scanlogging "go-server/internal/services/sonarqube/scanner/logging"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultScanLogPrefix       = "sonarqube:scan:logs"
	defaultScanLogHistoryLimit = int64(2000)
	defaultScanLogTTL          = 24 * time.Hour
	defaultScanLogReadLimit    = 200
)

type storedScanLog struct {
	ScanID           string    `json:"scan_id"`
	Phase            string    `json:"phase,omitempty"`
	Level            string    `json:"level"`
	Line             string    `json:"line"`
	Timestamp        time.Time `json:"timestamp"`
	SequenceNum      int64     `json:"sequence_num"`
	IsFinalChunk     bool      `json:"is_final_chunk,omitempty"`
	CompletionStatus string    `json:"completion_status,omitempty"`
}

type scanLogSink struct {
	server *ScannerServer
	scanID uuid.UUID
}

func (s scanLogSink) Record(ctx context.Context, level, line string) {
	if s.server == nil {
		return
	}
	s.server.publishScanLog(s.scanID, scanlogging.Phase(ctx), level, line, "", false)
}

func (s *ScannerServer) GetScanLogs(ctx context.Context, req *pb.ScanLogsRequest) (*pb.ScanLogsResponse, error) {
	scan, err := s.getScan(ctx, req.GetScanId())
	if err != nil {
		return nil, err
	}

	logs, err := s.readScanLogs(ctx, scan.ID.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read scan logs: %v", err)
	}

	filtered := filterScanLogs(logs, req.GetPhases(), req.GetAfterSequenceNum())
	limit := normalizeScanLogLimit(req.GetLimit())
	if req.GetAfterSequenceNum() == 0 {
		filtered = tailScanLogs(filtered, limit)
	} else if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return &pb.ScanLogsResponse{
		Logs:            filtered,
		IsTerminal:      isTerminalStatus(scan.Status),
		Status:          scanStatus(scan.Status),
		NextSequenceNum: nextScanLogSequence(logs),
	}, nil
}

func (s *ScannerServer) StreamScanLogs(req *pb.StreamScanLogsRequest, stream pb.SonarqubeService_StreamScanLogsServer) error {
	scanID, err := parseScanID(req.GetScanId())
	if err != nil {
		return err
	}
	if _, err := s.getScan(stream.Context(), scanID.String()); err != nil {
		return err
	}

	lastSentSequence := int64(0)
	if req.GetIncludeHistory() {
		logs, readErr := s.readScanLogs(stream.Context(), scanID.String())
		if readErr != nil {
			return status.Errorf(codes.Internal, "read scan logs: %v", readErr)
		}
		history := filterScanLogs(logs, req.GetPhases(), 0)
		history = tailScanLogs(history, normalizeScanLogLimit(req.GetHistoryLimit()))
		for _, chunk := range history {
			if err := stream.Send(chunk); err != nil {
				return err
			}
			lastSentSequence = chunk.GetSequenceNum()
		}
	} else {
		logs, readErr := s.readScanLogs(stream.Context(), scanID.String())
		if readErr != nil {
			return status.Errorf(codes.Internal, "read scan logs: %v", readErr)
		}
		lastSentSequence = nextScanLogSequence(logs) - 1
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			logs, readErr := s.readScanLogs(stream.Context(), scanID.String())
			if readErr != nil {
				return status.Errorf(codes.Internal, "read scan logs: %v", readErr)
			}

			liveLogs := filterScanLogs(logs, req.GetPhases(), lastSentSequence)
			for _, chunk := range liveLogs {
				if err := stream.Send(chunk); err != nil {
					return err
				}
				lastSentSequence = chunk.GetSequenceNum()
				if chunk.GetIsFinalChunk() {
					return nil
				}
			}

			scan, scanErr := s.scanRepo.RawByUUID(stream.Context(), scanID)
			if scanErr != nil {
				return status.Errorf(codes.Internal, "read scan: %v", scanErr)
			}
			if isTerminalStatus(scan.Status) {
				return nil
			}
		}
	}
}

func (s *ScannerServer) scanLogger(ctx context.Context, scanID uuid.UUID, projectKey string) context.Context {
	logger := s.logger.With().
		Str("scan_id", scanID.String()).
		Str("project_key", strings.TrimSpace(projectKey)).
		Logger()

	ctx = logger.WithContext(ctx)
	ctx = scanlogging.WithSink(ctx, scanLogSink{server: s, scanID: scanID})
	return ctx
}

func (s *ScannerServer) phaseLogger(ctx context.Context, phase string) context.Context {
	phase = strings.TrimSpace(phase)
	ctx = scanlogging.WithPhase(ctx, phase)

	base := zerolog.Ctx(ctx)
	if base == nil || base.GetLevel() == zerolog.Disabled {
		fallback := s.logger
		base = &fallback
	}
	logger := base.With().Str("phase", phase).Logger()
	return logger.WithContext(ctx)
}

func (s *ScannerServer) logInfo(ctx context.Context, message string) {
	scanlogging.Info(ctx, message)
	zerolog.Ctx(ctx).Info().Msg(message)
}

func (s *ScannerServer) logWarn(ctx context.Context, message string) {
	scanlogging.Warn(ctx, message)
	zerolog.Ctx(ctx).Warn().Msg(message)
}

func (s *ScannerServer) logError(ctx context.Context, message string) {
	scanlogging.Error(ctx, message)
	zerolog.Ctx(ctx).Error().Msg(message)
}

func (s *ScannerServer) completeScanLog(scanID uuid.UUID, statusText, message string) {
	statusText = strings.ToUpper(strings.TrimSpace(statusText))
	if message == "" {
		message = fmt.Sprintf("scan finished with status %s", statusText)
	}
	level := scanlogging.LevelInfo
	if statusText == scanStatusFailed {
		level = scanlogging.LevelError
	}
	s.publishScanLog(scanID, "scan", level, message, statusText, true)
}

func (s *ScannerServer) publishScanLog(scanID uuid.UUID, phase, level, line, completionStatus string, isFinal bool) {
	if s.redisClient == nil {
		return
	}

	line = strings.TrimSpace(strings.TrimRight(line, "\r"))
	if line == "" {
		return
	}

	phase = strings.TrimSpace(phase)
	level = normalizeScanLogLevel(level)
	completionStatus = strings.ToUpper(strings.TrimSpace(completionStatus))
	now := time.Now().UTC()
	entry := storedScanLog{
		ScanID:           scanID.String(),
		Phase:            phase,
		Level:            level,
		Line:             line,
		Timestamp:        now,
		IsFinalChunk:     isFinal,
		CompletionStatus: completionStatus,
	}

	pubCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s.logMu.Lock()
	defer s.logMu.Unlock()

	seq, err := s.redisClient.Incr(pubCtx, s.scanLogSequenceKey(scanID.String())).Result()
	if err != nil {
		return
	}
	entry.SequenceNum = seq
	body, err := json.Marshal(entry)
	if err != nil {
		return
	}

	pipe := s.redisClient.TxPipeline()
	pipe.RPush(pubCtx, s.scanLogHistoryKey(scanID.String()), body)
	pipe.LTrim(pubCtx, s.scanLogHistoryKey(scanID.String()), -s.scanLogHistoryLimit, -1)
	pipe.Expire(pubCtx, s.scanLogHistoryKey(scanID.String()), s.scanLogTTL)
	pipe.Expire(pubCtx, s.scanLogSequenceKey(scanID.String()), s.scanLogTTL)
	pipe.Publish(pubCtx, s.scanLogChannel(scanID.String()), body)
	_, _ = pipe.Exec(pubCtx)
}

func (s *ScannerServer) readScanLogs(ctx context.Context, scanID string) ([]*pb.ScanLogChunk, error) {
	if s.redisClient == nil {
		return nil, nil
	}
	values, err := s.redisClient.LRange(ctx, s.scanLogHistoryKey(scanID), 0, -1).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	logs := make([]*pb.ScanLogChunk, 0, len(values))
	for _, value := range values {
		var entry storedScanLog
		if unmarshalErr := json.Unmarshal([]byte(value), &entry); unmarshalErr != nil {
			continue
		}
		logs = append(logs, &pb.ScanLogChunk{
			ScanId:           entry.ScanID,
			Phase:            entry.Phase,
			Level:            entry.Level,
			Line:             entry.Line,
			Timestamp:        timestamppb.New(entry.Timestamp),
			SequenceNum:      entry.SequenceNum,
			IsFinalChunk:     entry.IsFinalChunk,
			CompletionStatus: scanStatus(entry.CompletionStatus),
		})
	}
	return logs, nil
}

func (s *ScannerServer) scanLogHistoryKey(scanID string) string {
	return fmt.Sprintf("%s:%s:history", s.scanLogPrefix, scanID)
}

func (s *ScannerServer) scanLogSequenceKey(scanID string) string {
	return fmt.Sprintf("%s:%s:seq", s.scanLogPrefix, scanID)
}

func (s *ScannerServer) scanLogChannel(scanID string) string {
	return fmt.Sprintf("%s:%s:live", s.scanLogPrefix, scanID)
}

func filterScanLogs(logs []*pb.ScanLogChunk, phases []string, afterSequenceNum int64) []*pb.ScanLogChunk {
	allowed := make(map[string]struct{}, len(phases))
	for _, phase := range phases {
		phase = strings.ToLower(strings.TrimSpace(phase))
		if phase == "" {
			continue
		}
		allowed[phase] = struct{}{}
	}

	filtered := make([]*pb.ScanLogChunk, 0, len(logs))
	for _, chunk := range logs {
		if chunk.GetSequenceNum() <= afterSequenceNum {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[strings.ToLower(strings.TrimSpace(chunk.GetPhase()))]; !ok {
				continue
			}
		}
		filtered = append(filtered, chunk)
	}
	return filtered
}

func tailScanLogs(logs []*pb.ScanLogChunk, limit int) []*pb.ScanLogChunk {
	if limit <= 0 || len(logs) <= limit {
		return append([]*pb.ScanLogChunk(nil), logs...)
	}
	return append([]*pb.ScanLogChunk(nil), logs[len(logs)-limit:]...)
}

func nextScanLogSequence(logs []*pb.ScanLogChunk) int64 {
	if len(logs) == 0 {
		return 1
	}
	return logs[len(logs)-1].GetSequenceNum() + 1
}

func normalizeScanLogLimit(value int32) int {
	switch {
	case value <= 0:
		return defaultScanLogReadLimit
	case value > 1000:
		return 1000
	default:
		return int(value)
	}
}

func normalizeScanLogLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case scanlogging.LevelWarn:
		return scanlogging.LevelWarn
	case scanlogging.LevelError:
		return scanlogging.LevelError
	default:
		return scanlogging.LevelInfo
	}
}

func scanLogPrefixFromEnv() string {
	prefix := strings.TrimSpace(os.Getenv("SONARQUBE_SCAN_LOG_PREFIX"))
	if prefix != "" {
		return prefix
	}
	prefix = strings.TrimSpace(os.Getenv("REDIS_SCAN_LOG_PREFIX"))
	if prefix != "" {
		return prefix
	}
	return defaultScanLogPrefix
}

func scanLogHistoryLimitFromEnv() int64 {
	raw := strings.TrimSpace(os.Getenv("SONARQUBE_SCAN_LOG_LIMIT"))
	if raw == "" {
		return defaultScanLogHistoryLimit
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return defaultScanLogHistoryLimit
	}
	return int64(value)
}

func scanLogTTLFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SONARQUBE_SCAN_LOG_TTL"))
	if raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}

	raw = strings.TrimSpace(os.Getenv("SONARQUBE_SCAN_LOG_TTL_SECONDS"))
	if raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}

	return defaultScanLogTTL
}
