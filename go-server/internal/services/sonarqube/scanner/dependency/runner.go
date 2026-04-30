package dependency

import (
	"context"
	"fmt"
	"sort"
	"sync"

	appconfig "go-server/pkg/config"

	"github.com/rs/zerolog"
)

type Logger = zerolog.Logger
type Config = appconfig.Config
type ScannerFunc func(ctx context.Context, sourceDir string) ([]*Finding, error)

type Runner struct {
	logger Logger
	cfg    Config
	scanners map[string]ScannerFunc
}

func NewRunner(logger Logger, cfg Config) *Runner {
	return &Runner{
		logger:   logger,
		cfg:      cfg,
		scanners: make(map[string]ScannerFunc),
	}
}

func (r *Runner) Run(ctx context.Context, sourceDir string) ([]*Finding, error) {
	languages := DetectLanguages(sourceDir)
	if len(languages) == 0 {
		r.logger.Info().Msg("no dependency manifests detected, skipping")
		return nil, nil
	}

	r.logger.Info().
		Int("count", len(languages)).
		Strs("languages", languageNames(languages)).
		Msg("detected languages")

	var mu sync.Mutex
	var wg sync.WaitGroup
	allFindings := make([]*Finding, 0)

	for _, language := range languages {
		language := language
		wg.Add(1)
		go func() {
			defer wg.Done()

			r.logger.Info().
				Str("language", language.Name).
				Str("manifest", language.ManifestPath).
				Msg("scanning language")

			findings, err := r.runForLanguage(ctx, language, sourceDir)
			if err != nil {
				r.logger.Warn().
					Str("language", language.Name).
					Err(err).
					Msg("language scan failed")
				return
			}

			r.logger.Info().
				Str("language", language.Name).
				Int("findings", len(findings)).
				Msg("language scan complete")

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return allFindings, nil
}

func (r *Runner) runForLanguage(ctx context.Context, language DetectedLanguage, sourceDir string) ([]*Finding, error) {
	scanner, ok := r.scanners[language.Name]
	if !ok && language.Name == "kotlin" {
		scanner, ok = r.scanners["java"]
	}
	if !ok {
		r.logger.Warn().
			Str("language", language.Name).
			Msg("no scanner registered for language")
		return nil, nil
	}
	findings, err := scanner(ctx, sourceDir)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *Runner) RegisterScanner(language string, scanner ScannerFunc) error {
	language = normalizeLanguageKey(language)
	if language == "" {
		return fmt.Errorf("language is required")
	}
	if scanner == nil {
		return fmt.Errorf("scanner is required")
	}
	r.scanners[language] = scanner
	return nil
}

func (r *Runner) RegisterScanners(scanners map[string]ScannerFunc) error {
	for language, scanner := range scanners {
		if err := r.RegisterScanner(language, scanner); err != nil {
			return err
		}
	}
	return nil
}

func normalizeLanguageKey(language string) string {
	switch language {
	case "":
		return ""
	default:
		return language
	}
}

func languageNames(languages []DetectedLanguage) []string {
	if len(languages) == 0 {
		return nil
	}
	names := make([]string, 0, len(languages))
	for _, language := range languages {
		names = append(names, language.Name)
	}
	sort.Strings(names)
	return names
}
