package sonar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/sync/errgroup"

	db "go-server/internal/database/sqlc"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	defaultCETaskWait  = 15 * time.Minute
	cePollInterval     = 3 * time.Second
	ruleCacheTTL       = 5 * time.Minute
)

var summaryMetricKeys = []string{
	"bugs",
	"vulnerabilities",
	"code_smells",
	"coverage",
	"duplicated_lines_density",
	"security_hotspots",
}

type Client struct {
	baseURL     string
	token       string
	httpClient  *http.Client
	store       sonarResultStore
	ruleDetails sync.Map
}

type ClientConfig struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	Store      sonarResultStore
}

type sonarResultStore interface {
	UpsertScanSonarResult(ctx context.Context, arg db.UpsertScanSonarResultParams) (db.ScanSonarResult, error)
}

type IssueFilters map[string]string

type Issue struct {
	Key       string    `json:"key"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	RuleKey   string    `json:"rule_key"`
	Message   string    `json:"message"`
	FilePath  string    `json:"file_path"`
	Line      int32     `json:"line"`
	Status    string    `json:"status"`
	Tags      []string  `json:"tags"`
	Component string    `json:"component"`
	TextRange TextRange `json:"text_range"`
}

type TextRange struct {
	StartLine   int32 `json:"start_line"`
	EndLine     int32 `json:"end_line"`
	StartOffset int32 `json:"start_offset"`
	EndOffset   int32 `json:"end_offset"`
}

type IssueDetail struct {
	WhereIsIssue IssueWhere    `json:"where_is_issue"`
	WhyIsIssue   IssueWhy      `json:"why_is_issue"`
	Activity     IssueActivity `json:"activity"`
	MoreInfo     IssueMoreInfo `json:"more_info"`
}

type IssueWhere struct {
	ComponentKey string    `json:"component_key"`
	FilePath     string    `json:"file_path"`
	Line         int32     `json:"line"`
	TextRange    TextRange `json:"text_range"`
	CodeSnippet  string    `json:"code_snippet"`
}

type IssueWhy struct {
	IssueMessage string   `json:"issue_message"`
	Severity     string   `json:"severity"`
	Status       string   `json:"status"`
	Tags         []string `json:"tags"`
	RuleKey      string   `json:"rule_key"`
	RuleName     string   `json:"rule_name"`
	HTMLDesc     string   `json:"html_desc"`
}

type IssueActivity struct {
	Comments  []ActivityComment `json:"comments"`
	Changelog []ActivityChange  `json:"changelog"`
}

type ActivityComment struct {
	Key       string `json:"key"`
	Login     string `json:"login"`
	HTMLText  string `json:"html_text"`
	CreatedAt string `json:"created_at"`
}

type ActivityChange struct {
	CreatedAt string         `json:"created_at"`
	User      string         `json:"user"`
	Diffs     []ActivityDiff `json:"diffs"`
}

type ActivityDiff struct {
	Key      string `json:"key"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

type IssueMoreInfo struct {
	DocumentationURL    string               `json:"documentation_url"`
	DescriptionSections []DescriptionSection `json:"description_sections"`
}

type DescriptionSection struct {
	Key     string `json:"key"`
	Content string `json:"content"`
}

type cachedRuleDetail struct {
	detail    ruleDetail
	expiresAt time.Time
}

type ruleDetail struct {
	Name                string
	HTMLDesc            string
	DocumentationURL    string
	DescriptionSections []DescriptionSection
}

func NewClient(store db.Querier) (*Client, error) {
	return NewClientWithConfig(ClientConfig{
		BaseURL: firstEnv("", "SONAR_HOST_URL", "SONARQUBE_HOST", "SONARQUBE_BASE_URL"),
		Token:   firstEnv("", "SONAR_TOKEN", "SONARQUBE_TOKEN"),
		Store:   store,
	})
}

func NewClientWithConfig(cfg ClientConfig) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("sonar base URL is required: set SONAR_HOST_URL or SONARQUBE_HOST")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid sonar base URL %q: %w", baseURL, err)
	}

	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		return nil, errors.New("sonar token is required: set SONAR_TOKEN or SONARQUBE_TOKEN")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	} else if httpClient.Timeout == 0 {
		copyClient := *httpClient
		copyClient.Timeout = defaultHTTPTimeout
		httpClient = &copyClient
	}

	return &Client{
		baseURL:    baseURL,
		token:      token,
		httpClient: httpClient,
		store:      cfg.Store,
	}, nil
}

func GenerateSonarProjectKey(projectKey, scanID string) string {
	projectKey = strings.TrimSpace(projectKey)
	shortID := strings.ReplaceAll(strings.TrimSpace(scanID), "-", "")
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	if projectKey == "" {
		return shortID
	}
	if shortID == "" {
		return projectKey
	}
	return fmt.Sprintf("%s-%s", projectKey, shortID)
}

// Waiting CE Task From SonarQube
func (c *Client) WaitForCETask(ctx context.Context, projectKey string) (string, error) {
	projectKey = strings.TrimSpace(projectKey)
	if projectKey == "" {
		return "", errors.New("sonar project key is required")
	}

	waitCtx, cancel := context.WithTimeout(ctx, defaultCETaskWait)
	defer cancel()

	ticker := time.NewTicker(cePollInterval)
	defer ticker.Stop()

	for {
		status, analysisID, hasTask, err := c.fetchCETaskStatus(waitCtx, projectKey)
		if err != nil {
			return "", err
		}

		switch strings.ToUpper(status) {
		case "SUCCESS":
			return analysisID, nil
		case "FAILED", "CANCELED", "CANCELLED":
			return "", fmt.Errorf("sonar compute engine task ended with status %s", status)
		case "":
			if !hasTask {
				return "", nil
			}
		}

		select {
		case <-waitCtx.Done():
			return "", fmt.Errorf("waiting for sonar compute engine task timed out after %s: %w", defaultCETaskWait, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

// FetchAndSaveSummary fetches SonarQube quality gate status and measures
func (c *Client) FetchAndSaveSummary(ctx context.Context, scanID, projectKey, analysisID string) error {
	if c.store == nil {
		return errors.New("database store is required to save sonar summary")
	}
	scanUUID, err := uuid.Parse(strings.TrimSpace(scanID))
	if err != nil {
		return fmt.Errorf("invalid scan ID: %w", err)
	}
	projectKey = strings.TrimSpace(projectKey)
	if projectKey == "" {
		return errors.New("sonar project key is required")
	}

	var gate qualityGateResponse
	if err := c.getJSON(ctx, "/api/qualitygates/project_status", url.Values{"projectKey": {projectKey}}, &gate); err != nil {
		return fmt.Errorf("fetch sonar quality gate: %w", err)
	}

	var measures measuresResponse
	if err := c.getJSON(ctx, "/api/measures/component", url.Values{
		"component":   {projectKey},
		"metricKeys":  {strings.Join(summaryMetricKeys, ",")},
		"additional":  {"metrics"},
		"branch":      nil,
		"pullRequest": nil,
	}, &measures); err != nil {
		return fmt.Errorf("fetch sonar measures: %w", err)
	}

	values := measuresByMetric(measures.Component.Measures)
	rawResponse, err := json.Marshal(map[string]any{
		"quality_gate": gate,
		"measures":     measures,
	})
	if err != nil {
		return fmt.Errorf("marshal sonar summary raw response: %w", err)
	}

	_, err = c.store.UpsertScanSonarResult(ctx, db.UpsertScanSonarResultParams{
		ScanID:           scanUUID,
		AnalysisID:       textValue(analysisID),
		QualityGate:      normalizeQualityGate(gate.ProjectStatus.Status),
		Bugs:             int32FromMetric(values["bugs"]),
		Vulnerabilities:  int32FromMetric(values["vulnerabilities"]),
		CodeSmells:       int32FromMetric(values["code_smells"]),
		Coverage:         float64FromMetric(values["coverage"]),
		Duplications:     float64FromMetric(values["duplicated_lines_density"]),
		SecurityHotspots: int32FromMetric(values["security_hotspots"]),
		RawResponse:      rawResponse,
	})
	if err != nil {
		return fmt.Errorf("save sonar summary: %w", err)
	}
	return nil
}

func (c *Client) DeleteProject(ctx context.Context, projectKey string) error {
	projectKey = strings.TrimSpace(projectKey)
	if projectKey == "" {
		return errors.New("sonar project key is required")
	}

	reqURL := c.baseURL + "/api/projects/delete?project=" + url.QueryEscape(projectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("delete sonar project %s returned %s: %s", projectKey, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func textValue(value string) pgtype.Text {
	value = strings.TrimSpace(value)
	return pgtype.Text{String: value, Valid: value != ""}
}

// FetchIssues fetches a page of issues for the given project key and filters, and returns the issues WITH total count of matching issues
func (c *Client) FetchIssues(ctx context.Context, projectKey string, filters IssueFilters, page, pageSize int) ([]*Issue, int, error) {
	projectKey = strings.TrimSpace(projectKey)
	if projectKey == "" {
		return nil, 0, errors.New("sonar project key is required")
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}

	query := url.Values{
		"componentKeys": {projectKey},
		"p":             {strconv.Itoa(page)},
		"ps":            {strconv.Itoa(pageSize)},
	}
	for key, value := range filters {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			query.Set(key, value)
		}
	}

	var response issuesSearchResponse
	if err := c.getJSON(ctx, "/api/issues/search", query, &response); err != nil {
		return nil, 0, err
	}
	return mapIssues(response.Issues), response.Total(), nil
}

// Fetch Issues Detail
func (c *Client) FetchIssueDetail(ctx context.Context, issueKey string) (*IssueDetail, error) {
	issueKey = strings.TrimSpace(issueKey)
	if issueKey == "" {
		return nil, errors.New("sonar issue key is required")
	}

	issue, err := c.fetchIssueByKey(ctx, issueKey)
	if err != nil {
		return nil, err
	}

	var (
		rule     ruleDetail
		snippet  string
		activity IssueActivity
	)
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var err error
		rule, err = c.fetchRuleDetail(groupCtx, issue.Rule)
		return err
	})
	group.Go(func() error {
		var err error
		snippet, err = c.fetchSourceSnippet(groupCtx, issue.Component, issue.Line, issue.TextRange)
		return err
	})
	group.Go(func() error {
		var err error
		activity, err = c.fetchIssueActivity(groupCtx, issue.Key)
		return err
	})
	if err := group.Wait(); err != nil {
		return nil, err
	}

	return &IssueDetail{
		WhereIsIssue: IssueWhere{
			ComponentKey: issue.Component,
			FilePath:     componentFilePath(issue.Component),
			Line:         int32(issue.Line),
			TextRange:    mapTextRange(issue.TextRange),
			CodeSnippet:  snippet,
		},
		WhyIsIssue: IssueWhy{
			IssueMessage: issue.Message,
			Severity:     issue.Severity,
			Status:       issue.Status,
			Tags:         issue.Tags,
			RuleKey:      issue.Rule,
			RuleName:     rule.Name,
			HTMLDesc:     rule.HTMLDesc,
		},
		Activity: activity,
		MoreInfo: IssueMoreInfo{
			DocumentationURL:    rule.DocumentationURL,
			DescriptionSections: rule.DescriptionSections,
		},
	}, nil
}

// Fetch CE Task Status, return status, whether task exists, error
func (c *Client) fetchCETaskStatus(ctx context.Context, projectKey string) (string, string, bool, error) {
	var response ceComponentResponse
	if err := c.getJSON(ctx, "/api/ce/component", url.Values{"component": {projectKey}}, &response); err != nil {
		return "", "", false, fmt.Errorf("fetch sonar compute engine component: %w", err)
	}
	if response.Current.Status != "" {
		return response.Current.Status, response.Current.AnalysisID, true, nil
	}
	if len(response.Queue) > 0 {
		return response.Queue[0].Status, response.Queue[0].AnalysisID, true, nil
	}
	return "", "", false, nil
}

// Fetches a sonar issue by Project key. Returns an error if the issue is not found or if the request fails.
func (c *Client) fetchIssueByKey(ctx context.Context, issueKey string) (sonarIssue, error) {
	var response issuesSearchResponse
	if err := c.getJSON(ctx, "/api/issues/search", url.Values{"issues": {issueKey}}, &response); err != nil {
		return sonarIssue{}, fmt.Errorf("fetch sonar issue: %w", err)
	}
	if len(response.Issues) == 0 {
		return sonarIssue{}, fmt.Errorf("sonar issue %q not found", issueKey)
	}
	return response.Issues[0], nil
}

// Fetches sonar rule details by rule key.
func (c *Client) fetchRuleDetail(ctx context.Context, ruleKey string) (ruleDetail, error) {
	ruleKey = strings.TrimSpace(ruleKey)
	if ruleKey == "" {
		return ruleDetail{}, nil
	}
	if cached, ok := c.ruleDetails.Load(ruleKey); ok {
		entry := cached.(cachedRuleDetail)
		if time.Now().Before(entry.expiresAt) {
			return entry.detail, nil
		}
		c.ruleDetails.Delete(ruleKey)
	}

	var response ruleShowResponse
	if err := c.getJSON(ctx, "/api/rules/show", url.Values{"key": {ruleKey}}, &response); err != nil {
		return ruleDetail{}, fmt.Errorf("fetch sonar rule %s: %w", ruleKey, err)
	}

	detail := ruleDetail{
		Name:                response.Rule.Name,
		HTMLDesc:            firstNonEmpty(response.Rule.HTMLDesc, response.Rule.HTMLDescription),
		DocumentationURL:    response.Rule.DocumentationURL,
		DescriptionSections: response.Rule.DescriptionSections,
	}
	c.ruleDetails.Store(ruleKey, cachedRuleDetail{detail: detail, expiresAt: time.Now().Add(ruleCacheTTL)})
	return detail, nil
}

// Fetch Source code snippet for the given component and line range.
func (c *Client) fetchSourceSnippet(ctx context.Context, component string, line int, textRange sonarTextRange) (string, error) {
	component = strings.TrimSpace(component)
	if component == "" {
		return "", nil
	}

	query := url.Values{"key": {component}}
	if line > 0 {
		from := line - 5
		if from < 1 {
			from = 1
		}
		to := line + 5
		if textRange.EndLine > to {
			to = textRange.EndLine + 5
		}
		query.Set("from", strconv.Itoa(from))
		query.Set("to", strconv.Itoa(to))
	}

	var response sourcesShowResponse
	if err := c.getJSON(ctx, "/api/sources/show", query, &response); err != nil {
		return "", fmt.Errorf("fetch sonar source snippet: %w", err)
	}
	return response.Snippet(), nil
}

// Fetch Issue activity, including comments and changelog, for the given issue key.
func (c *Client) fetchIssueActivity(ctx context.Context, issueKey string) (IssueActivity, error) {
	var response changelogResponse
	if err := c.getJSON(ctx, "/api/issues/changelog", url.Values{"issue": {issueKey}}, &response); err != nil {
		return IssueActivity{}, fmt.Errorf("fetch sonar issue changelog: %w", err)
	}

	activity := IssueActivity{
		Comments:  make([]ActivityComment, 0, len(response.Comments)),
		Changelog: make([]ActivityChange, 0, len(response.Changelog)),
	}
	for _, comment := range response.Comments {
		activity.Comments = append(activity.Comments, ActivityComment{
			Key:       comment.Key,
			Login:     firstNonEmpty(comment.Login, comment.User),
			HTMLText:  firstNonEmpty(comment.HTMLText, comment.Markdown),
			CreatedAt: firstNonEmpty(comment.CreatedAt, comment.CreationDate),
		})
	}
	for _, change := range response.Changelog {
		item := ActivityChange{
			CreatedAt: firstNonEmpty(change.CreatedAt, change.CreationDate),
			User:      firstNonEmpty(change.User, change.UserName, change.Login),
			Diffs:     make([]ActivityDiff, 0, len(change.Diffs)),
		}
		for _, diff := range change.Diffs {
			item.Diffs = append(item.Diffs, ActivityDiff{
				Key:      diff.Key,
				OldValue: diff.OldValue,
				NewValue: diff.NewValue,
			})
		}
		activity.Changelog = append(activity.Changelog, item)
	}
	return activity, nil
}

// getJSON performs a GET request to the given path with query parameters, and decodes the JSON response into out.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	reqURL := c.baseURL + path
	if len(query) > 0 {
		cleaned := url.Values{}
		for key, values := range query {
			for _, value := range values {
				if value != "" {
					cleaned.Add(key, value)
				}
			}
		}
		if encoded := cleaned.Encode(); encoded != "" {
			reqURL += "?" + encoded
		}
	}

	var lastErr error
	backoff := 250 * time.Millisecond
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
				lastErr = fmt.Errorf("sonar request %s returned %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
			} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return fmt.Errorf("sonar request %s returned %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
			} else if len(body) == 0 {
				return nil
			} else if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("decode sonar response %s: %w", path, err)
			} else {
				return nil
			}
		}

		if attempt < 3 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	return lastErr
}

type ceComponentResponse struct {
	Current ceTask   `json:"current"`
	Queue   []ceTask `json:"queue"`
}

type ceTask struct {
	Status     string `json:"status"`
	AnalysisID string `json:"analysisId"`
}

type qualityGateResponse struct {
	ProjectStatus struct {
		Status string `json:"status"`
	} `json:"projectStatus"`
}

type measuresResponse struct {
	Component struct {
		Measures []sonarMeasure `json:"measures"`
	} `json:"component"`
}

type sonarMeasure struct {
	Metric string `json:"metric"`
	Value  string `json:"value"`
}

type issuesSearchResponse struct {
	Issues   []sonarIssue `json:"issues"`
	TotalRaw int          `json:"total"`
	Paging   struct {
		Total int `json:"total"`
	} `json:"paging"`
}

func (r issuesSearchResponse) Total() int {
	if r.Paging.Total > 0 {
		return r.Paging.Total
	}
	return r.TotalRaw
}

type sonarIssue struct {
	Key       string         `json:"key"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	Rule      string         `json:"rule"`
	Message   string         `json:"message"`
	Component string         `json:"component"`
	Line      int            `json:"line"`
	Status    string         `json:"status"`
	Tags      []string       `json:"tags"`
	TextRange sonarTextRange `json:"textRange"`
}

type sonarTextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartOffset int `json:"startOffset"`
	EndOffset   int `json:"endOffset"`
}

type ruleShowResponse struct {
	Rule struct {
		Name                string               `json:"name"`
		HTMLDesc            string               `json:"htmlDesc"`
		HTMLDescription     string               `json:"htmlDescription"`
		DocumentationURL    string               `json:"documentationUrl"`
		DescriptionSections []DescriptionSection `json:"descriptionSections"`
	} `json:"rule"`
}

type sourcesShowResponse struct {
	Sources []json.RawMessage `json:"sources"`
}

func (r sourcesShowResponse) Snippet() string {
	lines := make([]string, 0, len(r.Sources))
	for _, raw := range r.Sources {
		var tuple []json.RawMessage
		if err := json.Unmarshal(raw, &tuple); err != nil || len(tuple) < 2 {
			continue
		}
		var lineNo int
		var code string
		_ = json.Unmarshal(tuple[0], &lineNo)
		_ = json.Unmarshal(tuple[1], &code)
		if lineNo > 0 {
			lines = append(lines, fmt.Sprintf("%d: %s", lineNo, code))
		} else {
			lines = append(lines, code)
		}
	}
	return strings.Join(lines, "\n")
}

type changelogResponse struct {
	Comments  []sonarComment `json:"comments"`
	Changelog []sonarChange  `json:"changelog"`
}

type sonarComment struct {
	Key          string `json:"key"`
	Login        string `json:"login"`
	User         string `json:"user"`
	HTMLText     string `json:"htmlText"`
	Markdown     string `json:"markdown"`
	CreatedAt    string `json:"createdAt"`
	CreationDate string `json:"creationDate"`
}

type sonarChange struct {
	CreatedAt    string      `json:"createdAt"`
	CreationDate string      `json:"creationDate"`
	User         string      `json:"user"`
	UserName     string      `json:"userName"`
	Login        string      `json:"login"`
	Diffs        []sonarDiff `json:"diffs"`
}

type sonarDiff struct {
	Key      string `json:"key"`
	OldValue string `json:"oldValue"`
	NewValue string `json:"newValue"`
}

func measuresByMetric(measures []sonarMeasure) map[string]string {
	values := make(map[string]string, len(measures))
	for _, measure := range measures {
		values[measure.Metric] = measure.Value
	}
	return values
}

func normalizeQualityGate(status string) string {
	status = strings.ToUpper(strings.TrimSpace(status))
	switch status {
	case "OK", "WARN", "ERROR":
		return status
	default:
		return "NONE"
	}
}

func int32FromMetric(value string) int32 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0
	}
	return int32(parsed)
}

func float64FromMetric(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}

func mapIssues(items []sonarIssue) []*Issue {
	issues := make([]*Issue, 0, len(items))
	for _, item := range items {
		issue := item
		issues = append(issues, &Issue{
			Key:       issue.Key,
			Type:      issue.Type,
			Severity:  issue.Severity,
			RuleKey:   issue.Rule,
			Message:   issue.Message,
			FilePath:  componentFilePath(issue.Component),
			Line:      int32(issue.Line),
			Status:    issue.Status,
			Tags:      issue.Tags,
			Component: issue.Component,
			TextRange: mapTextRange(issue.TextRange),
		})
	}
	return issues
}

func mapTextRange(textRange sonarTextRange) TextRange {
	return TextRange{
		StartLine:   int32(textRange.StartLine),
		EndLine:     int32(textRange.EndLine),
		StartOffset: int32(textRange.StartOffset),
		EndOffset:   int32(textRange.EndOffset),
	}
}

func componentFilePath(component string) string {
	if _, filePath, ok := strings.Cut(component, ":"); ok {
		return filePath
	}
	return component
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
