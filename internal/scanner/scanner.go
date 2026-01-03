package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/kozlm/scanropods/internal/helper"
	"github.com/kozlm/scanropods/internal/model"
	"github.com/kozlm/scanropods/internal/store"
)

type ScanRequest = model.ScanRequest

// base directories:
//
//	outputs: /.../outputs/<scanID>/...
//	reports: /.../reports/<scanID>/...
var (
	baseOutputsDir   = "/home/michal/GolandProjects/Scanropod/outputs"
	baseReportsDir   = "/home/michal/GolandProjects/Scanropod/reports"
	nucleiConfigPath = "/home/michal/GolandProjects/Scanropod/config/nuclei/nuclei-config.yaml"
	zapConfigPath    = "/home/michal/GolandProjects/Scanropod/config/zap/zap-config.yaml"

	activeCancel = struct {
		sync.Mutex
		cancelMap map[string]context.CancelFunc
	}{cancelMap: make(map[string]context.CancelFunc)}
)

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
	var scanFailed atomic.Bool

	// generate scan ID and create per-scan dirs
	id := uuid.New().String()
	scanReportsDir := filepath.Join(baseReportsDir, id)
	scanOutputsDir := filepath.Join(baseOutputsDir, id)
	log.Printf("[StartScan] created scan ID: %s, reports dir: %s, outputs dir: %s",
		id, scanReportsDir, scanOutputsDir)

	// ensure base and per-scan dirs
	helper.EnsureDir(baseReportsDir)
	helper.EnsureDir(baseOutputsDir)
	helper.EnsureDir(scanReportsDir)
	helper.EnsureDir(scanOutputsDir)

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
	store.SetStatus(id, result)

	go func(scanID string, scannerList []string, requestTargets []string, parentCtx context.Context) {
		var wGroup sync.WaitGroup

		for _, scanner := range scanners {
			wGroup.Add(1)
			go func(scannerName string) {
				defer wGroup.Done()
				log.Printf("[StartScan] starting scanner: %s", scannerName)
				if err := runSingleScanner(ctx, scannerName, request.Targets); err != nil {
					log.Printf("[StartScan] scanner %s failed: %v", scannerName, err)
					scanFailed.Store(true)
				}
				log.Printf("[StartScan] scanner finished: %s", scannerName)
			}(scanner)
		}
		wGroup.Wait()

		finished := result
		now := time.Now()
		finished.FinishedAt = &now

		if scanFailed.Load() {
			finished.Status = model.StatusFailed
		} else {
			finished.Status = model.StatusDone
		}

		store.SetResult(id, finished)
		store.SetStatus(id, finished)

		// cleanup
		activeCancel.Lock()
		delete(activeCancel.cancelMap, id)
		activeCancel.Unlock()
		log.Printf("[StartScan] scan %s finished and removed from activeCancel map", id)
	}(id, scanners, request.Targets, ctx)

	return id, nil
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

func runSingleScanner(ctx context.Context, name string, targets []string) error {
	log.Printf("[runSingleScanner] starting scanner '%s' on targets: %v", name, targets)

	switch strings.ToLower(name) {
	case "nikto":
		return runNikto(ctx, targets)
	case "nuclei":
		return runNuclei(ctx, targets)
	case "wapiti":
		return runWapiti(ctx, targets)
	case "zap":
		return runZap(ctx, targets)
	default:
		log.Printf("[runSingleScanner] unknown scanner: %s (skipping)", name)
		return nil
	}
}

// --- NIKTO ---

func runNikto(ctx context.Context, targets []string) error {
	log.Printf("[runNikto] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	plugins := []string{
		"tests", "cookies", "headers", "ssl", "httpoptions", "robots",
		"paths", "dictionary", "cgi", "content_search", "fileops",
		"msgs", "sitefiles", "clientaccesspolicy", "multiple_index",
		"shellshock", "strutschock", "apache_expect_xss", "put_del_test", "report_json",
	}
	pluginArg := strings.Join(plugins, ";")

	for _, target := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runNikto] context cancelled, stopping. Last target: %s", target)
			return nil
		default:
		}

		safeTarget := helper.SanitizeFilename(target)

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("nikto-%s-%d.json", safeTarget, time.Now().Unix()),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("nikto-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runNikto] scanning target: %s -> report: %s, output: %s",
			target, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"nikto",
			"-h", target,
			"-Tuning", "x6abd",
			"-Plugins", pluginArg,
			"-ask", "no",
			"-nointeractive",
			"-o", reportFile,
			"-Format", "json",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[runNikto] error running nikto for %s: %v (output: %s)", target, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runNikto] failed to write nikto output for %s to %s: %v", target, outputFile, writeErr)
		} else {
			log.Printf("[runNikto] nikto output written for %s: %s", target, outputFile)
		}

		if _, err := os.Stat(reportFile); err == nil {
			log.Printf("[runNikto] nikto report saved to %s", reportFile)
		} else {
			log.Printf("[runNikto] nikto did not produce report for %s (expected: %s): %v", target, reportFile, err)
			return fmt.Errorf("nikto did not produce report for %s", target)
		}
	}

	log.Printf("[runNikto] completed for all targets")
	return nil
}

// --- NUCLEI ---

func runNuclei(ctx context.Context, targets []string) error {
	log.Printf("[runNuclei] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runNuclei] context cancelled, stopping. Last target: %s", target)
			return nil
		default:
		}

		safeTarget := helper.SanitizeFilename(target)

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("nuclei-%s-%d.json", safeTarget, time.Now().Unix()),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("nuclei-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runNuclei] scanning target: %s -> report: %s, output: %s",
			target, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"nuclei",
			"-u", target,
			"-duc",
			"-ni",
			"-config", nucleiConfigPath,
			"-json-export", reportFile,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[runNuclei] error running nuclei for %s: %v (output: %s)", target, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runNuclei] failed to write nuclei output for %s to %s: %v", target, outputFile, writeErr)
		} else {
			log.Printf("[runNuclei] nuclei output written for %s: %s", target, outputFile)
		}

		if _, err := os.Stat(reportFile); err == nil {
			log.Printf("[runNuclei] nuclei report saved to %s", reportFile)
		} else {
			log.Printf("[runNuclei] nuclei did not produce report for %s (expected: %s): %v", target, reportFile, err)
			return fmt.Errorf("nuclei did not produce report for %s", target)
		}
	}

	log.Printf("[runNuclei] completed for all targets")
	return nil
}

// --- WAPITI ---

func runWapiti(ctx context.Context, targets []string) error {
	log.Printf("[runWapiti] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	mods := []string{
		"backup", "cms", "cookieflags", "crlf", "csp",
		"csrf", "exec", "file", "htaccess", "https_redirect",
		"ldap", "log4shell", "methods", "permanentxss", "http_headers",
		"redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf",
		"upload", "wp_enum", "xss", "xxe",
	}
	modArg := strings.Join(mods, ",")

	for _, target := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runWapiti] context cancelled, stopping. Last target: %s", target)
			return nil
		default:
		}

		safeTarget := helper.SanitizeFilename(target)

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("wapiti-%s-%d.json", safeTarget, time.Now().Unix()),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("wapiti-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runWapiti] scanning target: %s -> report: %s, output: %s",
			target, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"wapiti",
			"--flush-session",
			"-m", modArg,
			"-u", target,
			"--scope", "page",
			"-f", "json",
			"-o", reportFile,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[runWapiti] error running wapiti for %s: %v (output: %s)", target, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runWapiti] failed to write wapiti output for %s to %s: %v", target, outputFile, writeErr)
		} else {
			log.Printf("[runWapiti] wapiti output written for %s: %s", target, outputFile)
		}

		if _, err := os.Stat(reportFile); err == nil {
			log.Printf("[runWapiti] wapiti report saved to %s", reportFile)
		} else {
			log.Printf("[runWapiti] wapiti did not produce report for %s (expected: %s): %v", target, reportFile, err)
			return fmt.Errorf("wapiti did not produce report for %s", target)
		}
	}

	log.Printf("[runWapiti] completed for all targets")
	return nil
}

// --- ZAP ---

func runZap(ctx context.Context, targets []string) error {
	log.Printf("[runZap] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runZap] context cancelled, stopping. Last target: %s", target)
			return nil
		default:
		}

		safeTarget := helper.SanitizeFilename(target)

		reportFileName := fmt.Sprintf("zap-%s-%d.json", safeTarget, time.Now().Unix())

		reportFile := filepath.Join(
			reportDir,
			reportFileName,
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("zap-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runZap] scanning target: %s -> report: %s, output: %s",
			target, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"zap",
			"-cmd",
			"-autorun", zapConfigPath,
		)
		env := os.Environ()
		env = append(env, "SCANROPOD_TARGET_URL="+target)
		env = append(env, "SCANROPOD_REPORT_DIR="+reportDir)
		env = append(env, "SCANROPOD_REPORT_FILE="+reportFileName)
		cmd.Env = env

		output, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("[runZap] error running zap for %s: %v (output: %s)", target, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runZap] failed to write zap output for %s to %s: %v", target, outputFile, writeErr)
		} else {
			log.Printf("[runZap] zap output written for %s: %s", target, outputFile)
		}

		if _, err := os.Stat(reportFile); err == nil {
			log.Printf("[runZap] zap report saved to %s", reportFile)
		} else {
			log.Printf("[runZap] zap did not produce report for %s (expected: %s): %v", target, reportFile, err)
			return fmt.Errorf("zap did not produce report for %s", target)
		}
	}

	log.Printf("[runZap] completed for all targets")
	return nil
}
