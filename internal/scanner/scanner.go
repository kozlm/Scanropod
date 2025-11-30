package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kozlm/scanropods/internal/models"
	"github.com/kozlm/scanropods/internal/store"
)

type ScanRequest = models.ScanRequest

// base directories:
//
//	outputs: /.../outputs/<scanID>/...
//	reports: /.../reports/<scanID>/...
var (
	baseOutputsDir   = "/home/michal/GolandProjects/Scanropod/outputs"
	baseReportsDir   = "/home/michal/GolandProjects/Scanropod/reports"
	nucleiConfigPath = "/home/michal/GolandProjects/Scanropod/configs/nuclei/nuclei-config.yaml"

	activeCancel = struct {
		sync.Mutex
		m map[string]context.CancelFunc
	}{m: make(map[string]context.CancelFunc)}
)

type ctxKey string

const (
	reportsDirCtxKey ctxKey = "reportsDir"
	outputsDirCtxKey ctxKey = "outputsDir"
)

// ensureDir makes sure given directory exists
func ensureDir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[scanner] failed to create dir %s: %v", dir, err)
	}
}

// sanitizeFilename makes URL safe for use as filename
func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	r := strings.NewReplacer(
		"://", "_",
		":", "_",
		"/", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		" ", "_",
	)
	return r.Replace(s)
}

func reportsDirFromCtx(ctx context.Context) string {
	if v := ctx.Value(reportsDirCtxKey); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return baseReportsDir
}

func outputsDirFromCtx(ctx context.Context) string {
	if v := ctx.Value(outputsDirCtxKey); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return baseOutputsDir
}

// StartScan initializes and runs requested scanners in parallel
func StartScan(req *ScanRequest) (string, error) {
	log.Printf("[StartScan] called with request: %+v", req)

	if req == nil || len(req.Targets) == 0 {
		log.Printf("[StartScan] error: no targets")
		return "", errors.New("no targets")
	}

	// generate scan ID and create per-scan dirs
	id := uuid.New().String()
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
	activeCancel.m[id] = cancel
	activeCancel.Unlock()
	log.Printf("[StartScan] context and cancel stored for scan ID: %s", id)

	// default scanners if none provided
	scanners := req.Scanners
	if len(scanners) == 0 {
		scanners = []string{"zap", "nikto", "nuclei", "wapiti"}
	}
	log.Printf("[StartScan] scanners to run: %v", scanners)

	sr := models.ScanResult{
		ID:        id,
		Targets:   req.Targets,
		Scanners:  scanners,
		StartedAt: time.Now(),
		Done:      false,
	}
	store.SetStatus(id, sr)

	var wg sync.WaitGroup

	for _, sc := range scanners {
		wg.Add(1)
		go func(scannerName string) {
			defer wg.Done()
			log.Printf("[StartScan] starting scanner: %s", scannerName)
			runSingleScanner(ctx, scannerName, req.Targets)
			log.Printf("[StartScan] scanner finished: %s", scannerName)
		}(sc)
	}

	r := sr
	now := time.Now()
	r.FinishedAt = &now
	r.Done = true

	store.SetResult(id, r)
	store.SetStatus(id, r)

	// cleanup
	activeCancel.Lock()
	delete(activeCancel.m, id)
	activeCancel.Unlock()
	log.Printf("[StartScan] scan %s finished and removed from activeCancel map", id)

	return id, nil
}

// StopScan cancels active scan if possible
func StopScan(id string) error {
	log.Printf("[StopScan] called for id: %s", id)

	activeCancel.Lock()
	defer activeCancel.Unlock()
	if cancel, ok := activeCancel.m[id]; ok {
		cancel()
		delete(activeCancel.m, id)
		log.Printf("[StopScan] cancelled and removed scan id: %s", id)
		return nil
	}
	log.Printf("[StopScan] no active scan with id: %s", id)
	return fmt.Errorf("no active scan with id %s", id)
}

func runSingleScanner(ctx context.Context, name string, targets []string) {
	log.Printf("[runSingleScanner] starting scanner '%s' on targets: %v", name, targets)

	switch strings.ToLower(name) {
	case "nikto":
		runNikto(ctx, targets)
	case "nuclei":
		runNuclei(ctx, targets)
	case "wapiti":
		runWapiti(ctx, targets)
	case "zap":
		runZap(ctx, targets)
	default:
		log.Printf("[runSingleScanner] unknown scanner: %s (skipping)", name)
	}
	log.Printf("[runSingleScanner] scanner '%s' finished", name)
}

// --- NIKTO ---

func runNikto(ctx context.Context, targets []string) {
	log.Printf("[runNikto] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	plugins := []string{
		"tests", "cookies", "headers", "ssl", "httpoptions", "robots",
		"paths", "dictionary", "cgi", "content_search", "fileops",
		"msgs", "sitefiles", "clientaccesspolicy", "multiple_index",
		"shellshock", "strutschock", "apache_expect_xss", "put_del_test", "report_json",
	}
	pluginArg := "\"" + strings.Join(plugins, ";") + "\""

	for _, t := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runNikto] context cancelled, stopping. Last target: %s", t)
			return
		default:
		}

		safeTarget := sanitizeFilename(t)

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("nikto-%s-%d.json", safeTarget, time.Now().Unix()),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("nikto-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runNikto] scanning target: %s -> report: %s, output: %s",
			t, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"nikto",
			"-h", t,
			"-Tuning", "x6abd",
			"-Plugins", pluginArg,
			"-ask", "no",
			"-nointeractive",
			"-o", reportFile,
			"-Format", "json",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[runNikto] error running nikto for %s: %v (output: %s)", t, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runNikto] failed to write nikto output for %s to %s: %v", t, outputFile, writeErr)
		} else {
			log.Printf("[runNikto] nikto output written for %s: %s", t, outputFile)
		}
	}

	log.Printf("[runNikto] completed for all targets")
}

// --- NUCLEI ---

func runNuclei(ctx context.Context, targets []string) {
	log.Printf("[runNuclei] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)
	outputDir := outputsDirFromCtx(ctx)

	for _, t := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runNuclei] context cancelled, stopping. Last target: %s", t)
			return
		default:
		}

		safeTarget := sanitizeFilename(t)

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("nuclei-%s-%d.json", safeTarget, time.Now().Unix()),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("nuclei-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runNuclei] scanning target: %s -> report: %s, output: %s",
			t, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"nuclei",
			"-u", t,
			"-duc",
			"-ni",
			"-config", nucleiConfigPath,
			"-json-export", reportFile,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[runNuclei] error running nuclei for %s: %v (output: %s)", t, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runNuclei] failed to write nuclei output for %s to %s: %v", t, outputFile, writeErr)
		} else {
			log.Printf("[runNuclei] nuclei output written for %s: %s", t, outputFile)
		}
	}

	log.Printf("[runNuclei] completed for all targets")
}

// --- WAPITI ---

func runWapiti(ctx context.Context, targets []string) {
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

	for _, t := range targets {
		select {
		case <-ctx.Done():
			log.Printf("[runWapiti] context cancelled, stopping. Last target: %s", t)
			return
		default:
		}

		safeTarget := sanitizeFilename(t)

		reportFile := filepath.Join(
			reportDir,
			fmt.Sprintf("wapiti-%s-%d.json", safeTarget, time.Now().Unix()),
		)
		outputFile := filepath.Join(
			outputDir,
			fmt.Sprintf("wapiti-%s-%d.log", safeTarget, time.Now().Unix()),
		)

		log.Printf("[runWapiti] scanning target: %s -> report: %s, output: %s",
			t, reportFile, outputFile)

		cmd := exec.CommandContext(
			ctx,
			"wapiti",
			"--flush-session",
			"-m", modArg,
			"-u", t,
			"--scope", "folder",
			"-f", "json",
			"-o", reportFile,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[runWapiti] error running wapiti for %s: %v (output: %s)", t, err, string(output))
		}

		if writeErr := os.WriteFile(outputFile, output, 0o644); writeErr != nil {
			log.Printf("[runWapiti] failed to write wapiti output for %s to %s: %v", t, outputFile, writeErr)
		} else {
			log.Printf("[runWapiti] wapiti output written for %s: %s", t, outputFile)
		}
	}

	log.Printf("[runWapiti] completed for all targets")
}

// --- ZAP ---

func runZap(ctx context.Context, targets []string) {
	//log.Printf("[runZap] starting for targets: %v", targets)
	//
	//reportDir := reportsDirFromCtx(ctx)
	//outputDir := outputsDirFromCtx(ctx)
	//
	//zapScriptPath := "zap-baseline.py"
	//
	//for _, target := range targets {
	//	select {
	//	case <-ctx.Done():
	//		log.Printf("[runZap] context cancelled before starting target: %s", target)
	//		return
	//	default:
	//	}
	//
	//	safeTarget := sanitizeFilename(target)
	//	ts := time.Now().Unix()
	//
	//	reportFile := filepath.Join(reportDir, fmt.Sprintf("zap-%s-%d.json", safeTarget, ts))
	//	outputFile := filepath.Join(outputDir, fmt.Sprintf("zap-%s-%d.log", safeTarget, ts))
	//
	//	args := []string{
	//		"-t", target,
	//		"-J", reportFile,
	//	}
	//
	//	log.Printf("[runZap] running ZAP CLI for target: %s -> report: %s, output: %s",
	//		target, reportFile, outputFile)
	//
	//	cmd := exec.CommandContext(ctx, zapScriptPath, args...)
	//	cmd.Env = os.Environ()
	//
	//	outBytes, err := cmd.CombinedOutput()
	//
	//	if writeErr := os.WriteFile(outputFile, outBytes, 0o644); writeErr != nil {
	//		log.Printf("[runZap] failed to write zap output for %s to %s: %v", target, outputFile, writeErr)
	//	} else {
	//		log.Printf("[runZap] zap output written for %s: %s", target, outputFile)
	//	}
	//
	//	if err != nil {
	//		if ctx.Err() != nil {
	//			log.Printf("[runZap] zap command for %s stopped due to context cancellation", target)
	//			return
	//		}
	//		log.Printf("[runZap] error running zap for %s: %v (see %s for details)", target, err, outputFile)
	//		continue
	//	}
	//
	//	if _, err := os.Stat(reportFile); err == nil {
	//		log.Printf("[runZap] zap JSON report saved to %s", reportFile)
	//	} else {
	//		log.Printf("[runZap] zap did not produce JSON report for %s (expected: %s): %v", target, reportFile, err)
	//	}
	//}
	//
	//log.Printf("[runZap] completed CLI runs for all targets")
}
