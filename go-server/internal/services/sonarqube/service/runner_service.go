package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	sonarqubequeue "go-server/internal/services/sonarqube/queue"
	gitscanner "go-server/internal/services/sonarqube/scanner/git"
	"go-server/internal/services/sonarqube/scanner/repository"
	"go-server/internal/services/sonarqube/scanner/sonar"
)

func (s *ScannerServer) RunQueuedScan(ctx context.Context, payload sonarqubequeue.ScanTaskPayload) error {
	scanID, err := uuid.Parse(payload.ScanID)
	if err != nil {
		return fmt.Errorf("parse scan_id: %w", err)
	}

	scan, err := s.scanRepo.RawByUUID(ctx, scanID)
	if err != nil {
		if repository.IsNotFound(err) || errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("read queued scan: %w", err)
	}
	if strings.EqualFold(scan.Status, scanStatusCancelled) {
		if !scan.FinishedAt.Valid {
			s.finalizeCancelledScan(context.Background(), scanID)
		}
		return nil
	}
	if isTerminalStatus(scan.Status) {
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.registerRunningScan(scanID.String(), cancel)
	defer s.unregisterRunningScan(scanID.String())
	go s.monitorScanCancellation(runCtx, scanID, cancel)

	s.runFullScan(runCtx, scanID, scanRequest{
		RepoURL:    payload.RepoURL,
		ProjectKey: payload.ProjectKey,
		Branch:     payload.Branch,
	})
	return nil
}

func (s *ScannerServer) runFullScan(ctx context.Context, scanID uuid.UUID, req scanRequest) {
	scanRoot := filepath.Join(s.tmpRoot, scanID.String())
	tmpDir := filepath.Join(scanRoot, "source")
	defer func() { _ = os.RemoveAll(scanRoot) }()
	if s.scanMarkedCancelled(context.Background(), scanID) {
		s.finalizeCancelledScan(context.Background(), scanID)
		return
	}

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
		if s.scanMarkedCancelled(context.Background(), scanID) {
			s.logWarn(cloneCtx, scanCancelledMessage)
			s.updatePhase(ctx, scanID, "clone", phaseStatusFailed, scanCancelledMessage)
			s.finalizeCancelledScan(context.Background(), scanID)
			return
		}
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
		if s.scanMarkedCancelled(context.Background(), scanID) {
			s.logWarn(cloneCtx, scanCancelledMessage)
			s.updatePhase(ctx, scanID, "clone", phaseStatusFailed, scanCancelledMessage)
			s.finalizeCancelledScan(context.Background(), scanID)
			return
		}
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
	if s.scanMarkedCancelled(context.Background(), scanID) {
		s.finalizeCancelledScan(context.Background(), scanID)
		return
	}

	progressValue := atomic.Int32{}
	progressValue.Store(10)
	updateProgress := func(progress int32) {
		for {
			current := progressValue.Load()
			if progress <= current {
				return
			}
			if progressValue.CompareAndSwap(current, progress) {
				s.updateProgress(ctx, scanID, progress)
				return
			}
		}
	}

	sonarProjectKey := sonar.GenerateSonarProjectKey(req.ProjectKey, scanID.String())
	_ = s.scanRepo.UpdateSonarProjectKey(ctx, scanID.String(), sonarProjectKey)

	var wg sync.WaitGroup
	errs := make([]error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		phaseCtx := s.phaseLogger(ctx, "sonarqube")
		s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusRunning, "")
		s.logInfo(phaseCtx, fmt.Sprintf("starting SonarQube analysis with project key %s", sonarProjectKey))
		sonarProperties, err := prepareSonarProperties(phaseCtx, tmpDir)
		if err != nil {
			if s.scanMarkedCancelled(context.Background(), scanID) {
				errs[0] = context.Canceled
				s.logWarn(phaseCtx, scanCancelledMessage)
				s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, scanCancelledMessage)
				return
			}
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		if err := sonar.Run(phaseCtx, tmpDir, sonarProjectKey, req.Branch, sonarProperties); err != nil {
			if s.scanMarkedCancelled(context.Background(), scanID) {
				errs[0] = context.Canceled
				s.logWarn(phaseCtx, scanCancelledMessage)
				s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, scanCancelledMessage)
				return
			}
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, "waiting for SonarQube compute engine task")
		analysisID, err := s.sonarClient.WaitForCETask(phaseCtx, sonarProjectKey)
		if err != nil {
			if s.scanMarkedCancelled(context.Background(), scanID) {
				errs[0] = context.Canceled
				s.logWarn(phaseCtx, scanCancelledMessage)
				s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, scanCancelledMessage)
				return
			}
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		s.logInfo(phaseCtx, "fetching SonarQube summary")
		if err := s.sonarClient.FetchAndSaveSummary(phaseCtx, scanID.String(), sonarProjectKey, analysisID); err != nil {
			if s.scanMarkedCancelled(context.Background(), scanID) {
				errs[0] = context.Canceled
				s.logWarn(phaseCtx, scanCancelledMessage)
				s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, scanCancelledMessage)
				return
			}
			errs[0] = err
			s.logError(phaseCtx, err.Error())
			s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusFailed, err.Error())
			return
		}
		s.updatePhase(phaseCtx, scanID, "sonarqube", phaseStatusDone, "")
		updateProgress(phaseStatusProgress("sonarqube"))
		s.logInfo(phaseCtx, "SonarQube phase finished successfully")
	}()

	go func() {
		defer wg.Done()
		phaseCtx := s.phaseLogger(ctx, "dependency")
		s.updatePhase(phaseCtx, scanID, "dependency", phaseStatusRunning, "")
		s.logInfo(phaseCtx, "starting dependency analysis")

		findings, runErr := s.depRunner.Run(phaseCtx, tmpDir)
		saveErr := s.saveDependencyFindings(phaseCtx, scanID, findings)
		if saveErr != nil {
			s.logError(phaseCtx, saveErr.Error())
		}
		if s.scanMarkedCancelled(context.Background(), scanID) {
			errs[1] = context.Canceled
			s.logWarn(phaseCtx, scanCancelledMessage)
			s.updatePhase(phaseCtx, scanID, "dependency", phaseStatusFailed, scanCancelledMessage)
			return
		}
		if runErr != nil || saveErr != nil {
			errs[1] = errors.Join(runErr, saveErr)
			s.logError(phaseCtx, errs[1].Error())
			s.updatePhase(phaseCtx, scanID, "dependency", phaseStatusFailed, errs[1].Error())
			return
		}

		s.updatePhase(phaseCtx, scanID, "dependency", phaseStatusDone, "")
		updateProgress(phaseStatusProgress("dependency"))
		s.logInfo(phaseCtx, fmt.Sprintf("dependency phase finished successfully with %d finding(s)", len(findings)))
	}()

	wg.Wait()
	if s.scanMarkedCancelled(context.Background(), scanID) {
		s.finalizeCancelledScan(context.Background(), scanID)
		return
	}

	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}

	switch failed {
	case 0:
		updateProgress(100)
		s.updateStatus(ctx, scanID, scanStatusSuccess, "")
		s.completeScanLog(scanID, scanStatusSuccess, "")
	case 1:
		updateProgress(100)
		s.updateStatus(ctx, scanID, scanStatusPartial, "")
		s.completeScanLog(scanID, scanStatusPartial, "scan completed with partial results")
	default:
		updateProgress(100)
		s.updateStatus(ctx, scanID, scanStatusFailed, "all scanners failed")
		s.completeScanLog(scanID, scanStatusFailed, "all scanners failed")
	}

	_ = s.scanRepo.SetFinishedAt(ctx, scanID.String(), time.Now())
}

func phaseStatusProgress(phase string) int32 {
	switch phase {
	case "sonarqube":
		return 65
	case "dependency":
		return 85
	default:
		return 0
	}
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
