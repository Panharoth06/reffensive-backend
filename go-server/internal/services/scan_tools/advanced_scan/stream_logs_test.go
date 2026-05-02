package advancedscan

import (
	"testing"
	"time"

	advancedpb "go-server/gen/advanced"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSelectReplayableLogChunks_AppliesLimitAfterFiltering(t *testing.T) {
	t.Parallel()

	logChunks := []*advancedpb.LogChunk{
		{SequenceNum: 1, Line: "stdout one", Source: advancedpb.LogSource_LOG_SOURCE_STDOUT, Timestamp: timestamppb.New(time.Unix(10, 0))},
		{SequenceNum: 2, Line: "stderr two", Source: advancedpb.LogSource_LOG_SOURCE_STDERR, Timestamp: timestamppb.New(time.Unix(20, 0))},
		{SequenceNum: 3, Line: "stdout three", Source: advancedpb.LogSource_LOG_SOURCE_STDOUT, Timestamp: timestamppb.New(time.Unix(30, 0))},
	}

	replayChunks := selectReplayableLogChunks(logChunks, &advancedpb.StreamLogsRequest{
		IncludeHistory: true,
		HistoryLimit:   1,
		Filter: &advancedpb.LogFilter{
			Sources: []advancedpb.LogSource{advancedpb.LogSource_LOG_SOURCE_STDOUT},
		},
	})

	if len(replayChunks) != 1 {
		t.Fatalf("expected 1 replay chunk, got %d", len(replayChunks))
	}
	if replayChunks[0].GetSequenceNum() != 3 {
		t.Fatalf("expected latest matching chunk, got sequence %d", replayChunks[0].GetSequenceNum())
	}
}

func TestCollectLiveLogChunks_RespectsSequenceAndKeyword(t *testing.T) {
	t.Parallel()

	logChunks := []*advancedpb.LogChunk{
		{SequenceNum: 1, Line: "subfinder started", Source: advancedpb.LogSource_LOG_SOURCE_SYSTEM, Timestamp: timestamppb.New(time.Unix(10, 0))},
		{SequenceNum: 2, Line: "api.example.com", Source: advancedpb.LogSource_LOG_SOURCE_STDOUT, Timestamp: timestamppb.New(time.Unix(20, 0))},
		{SequenceNum: 3, Line: "www.example.com", Source: advancedpb.LogSource_LOG_SOURCE_STDOUT, Timestamp: timestamppb.New(time.Unix(30, 0))},
	}

	liveChunks := collectLiveLogChunks(logChunks, &advancedpb.LogFilter{
		Keyword: "www",
	}, 1)

	if len(liveChunks) != 1 {
		t.Fatalf("expected 1 live chunk, got %d", len(liveChunks))
	}
	if liveChunks[0].GetSequenceNum() != 3 {
		t.Fatalf("expected sequence 3, got %d", liveChunks[0].GetSequenceNum())
	}
}
