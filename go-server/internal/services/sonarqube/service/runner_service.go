package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	sonarqubequeue "go-server/internal/services/sonarqube/queue"
	gitscanner "go-server/internal/services/sonarqube/scanner/git"
	"go-server/internal/services/sonarqube/scanner/owasp"
	"go-server/internal/services/sonarqube/scanner/sonar"
	"go-server/internal/services/sonarqube/scanner/trivy"
)

// RunQueuedScan executes a scan from an Asynq payload.
func (s *ScannerServer) RunQueuedScan(ctx context.Context, payload sonarqubequeue.ScanTaskPayload) error {
	scanID, err := uuid.Parse(payload.ScanID)
	if err != nil {
		return fmt.Errorf("parse scan_id: %w", err)
	}
	s.runFullScan(ctx, scanID, scanRequest{
		RepoURL:    payload.RepoURL,
		ProjectKey: payload.ProjectKey,
		Branch:     payload.Branch,
	})
	return nil
}

// runFullScan clones the repository and runs all scanners concurrently.
func (s *ScannerServer) runFullScan(ctx context.Context, scanID uuid.UUID, req scanRequest) {
	scanRoot := filepath.Join(s.tmpRoot, scanID.String())
	tmpDir := filepath.Join(scanRoot, "source")
	defer func() { _ = os.RemoveAll(scanRoot) }()

	ctx = s.scanLogger(ctx, scanID, req.ProjectKey)
	scanCtx := s.phaseLogger(ctx, "scan")
	s.logInfo(scanCtx, fmt.Sprintf("starting full scan for repository %s", req.RepoURL))

	_ = s.scanRepo.SetStartedAt(ctx, scanID.String(), time.Now())
	s.updatePhase(ctx, scanID, "clone", phaseStatusRunning, "")
	s.updateProgress(ctx, scanID, 5)

	cloneCtx := s.phaseLogger(ctx, "clone")
	s.logInfo(cloneCtx, "resolving repository access")
	cloneTargets, err := s.cloneTargetsForScan(ctx, scanID, req.RepoURL)
	if err != nil {
		msg := fmt.Sprintf("Resolve repository access: %v", err)
		s.logError(cloneCtx, msg)
		s.updatePhase(ctx, scanID, "clone", phaseStatusFailed, msg)
		s.updateStatus(ctx, scanID, scanStatusFailed, msg)
		_ = s.scanRepo.SetFinishedAt(ctx, scanID.String(), time.Now())
		s.completeScanLog(scanID, scanStatusFailed, msg)
		return
	}
	s.logInfo(cloneCtx, fmt.Sprintf("resolved %d clone target(s)", len(cloneTargets)))

	var cloneErr error
	for idx, cloneTarget := range cloneTargets {
		_ = os.RemoveAll(tmpDir)
		s.logInfo(cloneCtx, fmt.Sprintf("cloning repository attempt %d/%d", idx+1, len(cloneTargets)))
		cloneErr = gitscanner.Clone(ctx, cloneTarget, req.Branch, tmpDir)
		if cloneErr == nil {
			s.logInfo(cloneCtx, "repository clone completed")
			break
		}
		s.logWarn(cloneCtx, fmt.Sprintf("clone attempt %d failed: %v", idx+1, cloneErr))
		if idx < len(cloneTargets)-1 && shouldRetryCloneWithNextTarget(cloneErr) {
			continue
		}
		break
	}

	if cloneErr != nil {
		msg := classifyCloneError(cloneErr, req.Branch)
		s.logError(cloneCtx, msg)
		s.updatePhase(ctx, scanID, "clone", phaseStatusFailed, msg)
		s.updateStatus(ctx, scanID, scanStatusFailed, msg)
		_ = s.scanRepo.SetFinishedAt(ctx, scanID.String(), time.Now())
		s.completeScanLog(scanID, scanStatusFailed, msg)
		return
	}
	s.updatePhase(ctx, scanID, "clone", phaseStatusDone, "")
	s.updateProgress(ctx, scanID, 10)
	s.logInfo(cloneCtx, "clone phase finished successfully")

	var wg sync.WaitGroup
	errs := make([]error, 3)

	wg.Add(3)
	go func() {
		defer wg.Done()
		phaseCtx := s.phaseLogger(ctx, "sonarqube")
		s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusRunning, "")
		s.logInfo(phaseCtx, "starting SonarQube analysis")
		if err := sonar.Run(phaseCtx, tmpDir, req.ProjectKey, req.Branch); err != nil {
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, "waiting for SonarQube compute engine task")
		if err := s.sonarClient.WaitForCETask(phaseCtx, req.ProjectKey); err != nil {
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, "fetching SonarQube summary")
		if err := s.sonarClient.FetchAndSaveSummary(phaseCtx, scanID.String(), req.ProjectKey); err != nil {
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusDone, "")
		s.updateProgress(phaseCtx, scanID, 40)
		s.logInfo(phaseCtx, "SonarQube phase finished successfully")
	}()

	go func() {
		defer wg.Done()
		phaseCtx := s.phaseLogger(ctx, "owasp")
		s.updatePhase(phaseCtx, scanID, "owasp", phaseStatusRunning, "")
		s.logInfo(phaseCtx, "starting OWASP dependency-check")
		owaspOut := filepath.Join(scanRoot, "owasp")
		if err := os.MkdirAll(owaspOut, 0o755); err != nil {
			errs[1] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "owasp", phaseStatusFailed, err.Error())
			return
		}
		if err := owasp.Run(phaseCtx, tmpDir, req.ProjectKey, owaspOut); err != nil {
			errs[1] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "owasp", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, "parsing OWASP report")
		findings, err := owasp.Parse(filepath.Join(owaspOut, "dependency-check-report.json"))
		if err != nil {
			errs[1] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "owasp", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, fmt.Sprintf("saving %d OWASP finding(s)", len(findings)))
		if err := s.saveOWASPFindings(phaseCtx, scanID, findings); err != nil {
			errs[1] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "owasp", phaseStatusFailed, err.Error())
			return
		}
		s.updatePhase(phaseCtx, scanID, "owasp", phaseStatusDone, "")
		s.updateProgress(phaseCtx, scanID, 70)
		s.logInfo(phaseCtx, "OWASP phase finished successfully")
	}()

	go func() {
		defer wg.Done()
		phaseCtx := s.phaseLogger(ctx, "trivy")
		s.updatePhase(phaseCtx, scanID, "trivy", phaseStatusRunning, "")
		s.logInfo(phaseCtx, "starting Trivy filesystem scan")
		trivyOut := filepath.Join(scanRoot, "trivy.json")
		if err := trivy.Run(phaseCtx, tmpDir, trivyOut); err != nil {
			errs[2] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "trivy", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, "parsing Trivy report")
		findings, err := trivy.Parse(trivyOut)
		if err != nil {
			errs[2] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "trivy", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, fmt.Sprintf("saving %d Trivy finding(s)", len(findings)))
		if err := s.saveTrivyFindings(phaseCtx, scanID, findings); err != nil {
			errs[2] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "trivy", phaseStatusFailed, err.Error())
			return
		}
		s.updatePhase(phaseCtx, scanID, "trivy", phaseStatusDone, "")
		s.updateProgress(phaseCtx, scanID, 100)
		s.logInfo(phaseCtx, "Trivy phase finished successfully")
	}()

	wg.Wait()

	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}
	switch failed {
	case 0:
		s.updateStatus(ctx, scanID, scanStatusSuccess, "")
		s.completeScanLog(scanID, scanStatusSuccess, "")
	case 1, 2:
		s.updateStatus(ctx, scanID, scanStatusPartial, "")
		s.completeScanLog(scanID, scanStatusPartial, "scan completed with partial results")
	default:
		s.updateStatus(ctx, scanID, scanStatusFailed, "All scanners failed")
		s.completeScanLog(scanID, scanStatusFailed, "all scanners failed")
	}
	_ = s.scanRepo.SetFinishedAt(ctx, scanID.String(), time.Now())
}

func classifyCloneError(err error, branch string) string {
	switch {
	case errors.Is(err, gitscanner.ErrRepoNotFound):
		return "Repository not found or inaccessible"
	case errors.Is(err, gitscanner.ErrBranchNotFound):
		return fmt.Sprintf("Branch %q does not exist", branch)
	case errors.Is(err, gitscanner.ErrAuthRequired):
		return "Repository is private - access denied"
	case errors.Is(err, gitscanner.ErrCloneTimeout):
		return "Repository clone timed out"
	default:
		return err.Error()
	}
}
