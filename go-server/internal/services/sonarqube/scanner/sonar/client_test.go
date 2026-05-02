package sonar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	db "go-server/internal/database/sqlc"
)

func TestGetJSONRetriesOnServerError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Header.Get("Authorization") != "Bearer token-1" {
			t.Fatalf("Authorization = %q, want Bearer token-1", r.Header.Get("Authorization"))
		}
		if attempts == 1 {
			http.Error(w, "temporary failure", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClientWithConfig(ClientConfig{BaseURL: server.URL, Token: "token-1"})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}

	var payload struct {
		OK bool `json:"ok"`
	}
	if err := client.getJSON(context.Background(), "/api/test", nil, &payload); err != nil {
		t.Fatalf("getJSON() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if !payload.OK {
		t.Fatal("payload.OK = false, want true")
	}
}

func TestFetchRuleDetailCachesForTTL(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/rules/show" {
			t.Fatalf("path = %q, want /api/rules/show", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "go:S100" {
			t.Fatalf("key = %q, want go:S100", r.URL.Query().Get("key"))
		}
		_, _ = w.Write([]byte(`{
			"rule": {
				"name": "Example rule",
				"htmlDesc": "<p>Rule description</p>",
				"documentationUrl": "https://sonar.example/rules/go/S100",
				"descriptionSections": [{"key": "intro", "content": "Details"}]
			}
		}`))
	}))
	defer server.Close()

	client, err := NewClientWithConfig(ClientConfig{BaseURL: server.URL, Token: "token-1"})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}

	first, err := client.fetchRuleDetail(context.Background(), "go:S100")
	if err != nil {
		t.Fatalf("first fetchRuleDetail() error = %v", err)
	}
	second, err := client.fetchRuleDetail(context.Background(), "go:S100")
	if err != nil {
		t.Fatalf("second fetchRuleDetail() error = %v", err)
	}
	if first.Name != "Example rule" || second.HTMLDesc != "<p>Rule description</p>" {
		t.Fatalf("unexpected cached details: first=%#v second=%#v", first, second)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestFetchIssuesMapsSonarResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/issues/search" {
			t.Fatalf("path = %q, want /api/issues/search", r.URL.Path)
		}
		if r.URL.Query().Get("componentKeys") != "project-1" {
			t.Fatalf("componentKeys = %q, want project-1", r.URL.Query().Get("componentKeys"))
		}
		if r.URL.Query().Get("severities") != "CRITICAL" {
			t.Fatalf("severities = %q, want CRITICAL", r.URL.Query().Get("severities"))
		}
		_, _ = w.Write([]byte(`{
			"paging": {"total": 1},
			"issues": [{
				"key": "issue-1",
				"type": "BUG",
				"severity": "CRITICAL",
				"rule": "go:S100",
				"message": "Fix this",
				"component": "project-1:main.go",
				"line": 12,
				"status": "OPEN",
				"tags": ["bug"],
				"textRange": {"startLine": 12, "endLine": 12, "startOffset": 1, "endOffset": 5}
			}]
		}`))
	}))
	defer server.Close()

	client, err := NewClientWithConfig(ClientConfig{BaseURL: server.URL, Token: "token-1"})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}

	issues, total, err := client.FetchIssues(context.Background(), "project-1", IssueFilters{"severities": "CRITICAL"}, 1, 50)
	if err != nil {
		t.Fatalf("FetchIssues() error = %v", err)
	}
	if total != 1 || len(issues) != 1 {
		t.Fatalf("total=%d len=%d, want 1 and 1", total, len(issues))
	}
	if issues[0].RuleKey != "go:S100" || issues[0].FilePath != "main.go" || issues[0].TextRange.StartLine != 12 {
		t.Fatalf("unexpected issue mapping: %#v", issues[0])
	}
}

func TestFetchAndSaveSummaryUpsertsMetrics(t *testing.T) {
	store := &summaryStore{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/qualitygates/project_status":
			_, _ = w.Write([]byte(`{"projectStatus":{"status":"ERROR"}}`))
		case "/api/measures/component":
			_, _ = w.Write([]byte(`{
				"component": {
					"measures": [
						{"metric": "bugs", "value": "1"},
						{"metric": "vulnerabilities", "value": "2"},
						{"metric": "code_smells", "value": "3"},
						{"metric": "coverage", "value": "84.5"},
						{"metric": "duplicated_lines_density", "value": "6.7"},
						{"metric": "security_hotspots", "value": "4"}
					]
				}
			}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(ClientConfig{
		BaseURL: server.URL,
		Token:   "token-1",
		Store:   store,
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}

	err = client.FetchAndSaveSummary(context.Background(), "11111111-1111-1111-1111-111111111111", "project-1")
	if err != nil {
		t.Fatalf("FetchAndSaveSummary() error = %v", err)
	}
	if store.params.QualityGate != "ERROR" ||
		store.params.Bugs != 1 ||
		store.params.Vulnerabilities != 2 ||
		store.params.CodeSmells != 3 ||
		store.params.Coverage != 84.5 ||
		store.params.Duplications != 6.7 ||
		store.params.SecurityHotspots != 4 {
		t.Fatalf("unexpected upsert params: %#v", store.params)
	}
	if len(store.params.RawResponse) == 0 {
		t.Fatal("RawResponse is empty")
	}
}

type summaryStore struct {
	params db.UpsertScanSonarResultParams
}

func (s *summaryStore) UpsertScanSonarResult(ctx context.Context, arg db.UpsertScanSonarResultParams) (db.ScanSonarResult, error) {
	s.params = arg
	return db.ScanSonarResult{}, nil
}
