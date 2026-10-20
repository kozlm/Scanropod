// Package scanner coordinates vulnerability scans: it manages scan
// lifecycle (starting, stopping, status tracking) and runs the external
// scanner binaries (zap, nikto, nuclei, wapiti) as subprocesses.
package scanner

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/kozlm/scanropod/internal/model"
	"github.com/kozlm/scanropod/internal/store"
)

type ScanRequest = model.ScanRequest

// base directories:
//
//	outputs: /.../outputs/<scanID>/...
//	reports: /.../reports/<scanID>/...
var (
	baseOutputsDir   string
	baseReportsDir   string
	nucleiConfigPath string
	zapConfigPath    string

	newUUID   = func() string { return uuid.New().String() }
	setStatus = store.SetStatus
	setResult = store.SetResult
	runScans  = runScansOnTargets

	activeCancel = struct {
		sync.Mutex
		cancelMap map[string]context.CancelFunc
	}{cancelMap: make(map[string]context.CancelFunc)}
)

func Init(baseDir string) {
	baseOutputsDir = filepath.Join(baseDir, "outputs")
	baseReportsDir = filepath.Join(baseDir, "reports")

	nucleiConfigPath = filepath.Join(baseDir, "config/nuclei/nuclei-config.yaml")
	zapConfigPath = filepath.Join(baseDir, "config/zap/zap-config.yaml")
}

type ctxKey string

const (
	reportsDirCtxKey ctxKey = "reportsDir"
	outputsDirCtxKey ctxKey = "outputsDir"
)

func reportsDirFromCtx(ctx context.Context) string {
	if value := ctx.Value(reportsDirCtxKey); value != nil {
		if str, ok := value.(string); ok && str != "" {
			return str
		}
	}
	return baseReportsDir
}

func outputsDirFromCtx(ctx context.Context) string {
	if value := ctx.Value(outputsDirCtxKey); value != nil {
		if str, ok := value.(string); ok && str != "" {
			return str
		}
	}
	return baseOutputsDir
}

// StartScan initializes and runs requested scanners in parallel
func StartScan(request *ScanRequest) (string, error) {
	log.Printf("[StartScan] called with request: %+v", request)

	// generate scan ID and create per-scan dirs
	id := newUUID()
	scanReportsDir := filepath.Join(baseReportsDir, id)
	scanOutputsDir := filepath.Join(baseOutputsDir, id)
	log.Printf("[StartScan] created scan ID: %s, reports dir: %s, outputs dir: %s",
		id, scanReportsDir, scanOutputsDir)

	// ensure base and per-scan dirs
	ensureDir(baseReportsDir)
	ensureDir(baseOutputsDir)
	ensureDir(scanReportsDir)
	ensureDir(scanOutputsDir)

	// context with cancel and per-scan dirs
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, reportsDirCtxKey, scanReportsDir)
	ctx = context.WithValue(ctx, outputsDirCtxKey, scanOutputsDir)

	activeCancel.Lock()
	activeCancel.cancelMap[id] = cancel
	activeCancel.Unlock()
	log.Printf("[StartScan] context and cancel stored for scan ID: %s", id)

	// default scanners if none provided
	scanners := request.Scanners
	if len(scanners) == 0 {
		scanners = []string{"zap", "nikto", "nuclei", "wapiti"}
	}
	log.Printf("[StartScan] scanners to run: %v", scanners)

	result := model.ScanResult{
		ID:        id,
		Targets:   request.Targets,
		Scanners:  scanners,
		StartedAt: time.Now(),
		Status:    model.StatusRunning,
	}
	setStatus(id, result)

	go func() {
		finished := result
		now := time.Now()
		finished.FinishedAt = &now
		finished.Status = runScans(ctx, scanners, request.Targets)
		setResult(id, finished)
		setStatus(id, finished)

		// cleanup
		activeCancel.Lock()
		delete(activeCancel.cancelMap, id)
		activeCancel.Unlock()
		log.Printf("[StartScan] scan %s finished and removed from activeCancel map", id)
	}()

	return id, nil
}

func runScansOnTargets(
	ctx context.Context,
	scanners []string,
	targets []string,
) model.ScanStatus {
	var scanFailed atomic.Bool
	var wGroup sync.WaitGroup

	for _, scanner := range scanners {
		wGroup.Add(1)
		go func(scannerName string) {
			defer wGroup.Done()
			log.Printf("[runScan] starting scanner: %s", scannerName)
			if err := runScanner(ctx, scannerName, targets); err != nil {
				log.Printf("[runScan] scanner %s failed: %v", scannerName, err)
				scanFailed.Store(true)
			}
			log.Printf("[runScan] scanner finished: %s", scannerName)
		}(scanner)
	}
	wGroup.Wait()

	if scanFailed.Load() {
		return model.StatusFailed
	} else {
		return model.StatusDone
	}
}

// StopScan cancels active scan if possible
func StopScan(id string) error {
	log.Printf("[StopScan] called for id: %s", id)

	activeCancel.Lock()
	defer activeCancel.Unlock()
	if cancel, ok := activeCancel.cancelMap[id]; ok {
		cancel()
		delete(activeCancel.cancelMap, id)
		log.Printf("[StopScan] cancelled and removed scan id: %s", id)
		return nil
	}
	log.Printf("[StopScan] no active scan with id: %s", id)
	return fmt.Errorf("no active scan with id %s", id)
}
