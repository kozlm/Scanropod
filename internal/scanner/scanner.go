package scanner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kozlm/scanropods/internal/models"
	"github.com/kozlm/scanropods/internal/store"
	"github.com/zaproxy/zap-api-go/zap"
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

	sr := models.ScanResult{
		ID:        id,
		StartedAt: time.Now(),
	}
	store.SetStatus(id, sr)

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

	var wg sync.WaitGroup
	// TODO deal with outCH
	outCh := make(chan models.Vulnerability, 100)

	for _, sc := range scanners {
		wg.Add(1)
		go func(scannerName string) {
			defer wg.Done()
			log.Printf("[StartScan] starting scanner: %s", scannerName)
			runSingleScanner(ctx, scannerName, req.Targets, outCh)
			log.Printf("[StartScan] scanner finished: %s", scannerName)
		}(sc)
	}

	// collector: waits for scanners to finish and then closes channel
	go func() {
		wg.Wait()
		close(outCh)
		log.Printf("[StartScan] all scanners completed, outCh closed")
	}()

	vulns := make([]models.Vulnerability, 0)
	for range outCh {

	}

	r := sr
	r.Vulnerabilities = vulns
	now := time.Now()
	r.FinishedAt = &now

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

func runSingleScanner(ctx context.Context, name string, targets []string, _ chan<- models.Vulnerability) {
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
	pluginArg := strings.Join(plugins, ",")

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
			"-o", reportFile, // report file
			"-Format", "json", // format json
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
			"-json-export", reportFile, // report file via nuclei mechanism
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
		"csrf", "exec", "file", "htaccess", "htp", "https_redirect",
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
			"-o", reportFile, // report path via wapiti mechanism
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
	log.Printf("[runZap] starting for targets: %v", targets)

	reportDir := reportsDirFromCtx(ctx)

	cfg := &zap.Config{
		Base:      "http://127.0.0.1:8080/JSON/",
		BaseOther: "http://127.0.0.1:8080/OTHER/",
		Proxy:     zap.DefaultProxy,
	}

	client, err := zap.NewClient(cfg)
	if err != nil {
		log.Fatalf("[runZap] failed to create zap client: %v", err)
	}

	core := client.Core()
	ascan := client.Ascan()
	pscan := client.Pscan()

	// enable passive scanner and allow it to scan
	if _, err := pscan.SetEnabled("true"); err != nil {
		log.Fatalf("[runZap] failed to enable passive scanner: %v", err)
	}
	if _, err := pscan.SetScanOnlyInScope("false"); err != nil {
		log.Fatalf("[runZap] failed to configure passive scanner scope: %v", err)
	}

	// enable all active scan rules
	if _, err := ascan.EnableAllScanners(""); err != nil {
		log.Fatalf("[runZap] failed to enable all scanners: %v", err)
	}

	// iterate over all targets
	for _, target := range targets {
		log.Printf("[runZap] === ZAP scan for target: %s ===", target)

		select {
		case <-ctx.Done():
			log.Printf("[runZap] context cancelled, stopping. Last target: %s", target)
			return
		default:
		}

		// 1) access URL once so passive scanner can start
		log.Printf("[runZap] Requesting URL for passive scan: %s", target)
		if _, err := core.AccessUrl(target, "true"); err != nil {
			log.Fatalf("[runZap] failed to access url %s: %v", target, err)
		}

		// 2) wait for passive scanner to finish
		for {
			select {
			case <-ctx.Done():
				log.Printf("[runZap] context cancelled while waiting for passive scan (target: %s)", target)
				return
			default:
			}

			rec, err := pscan.RecordsToScan()
			if err != nil {
				log.Fatalf("[runZap] failed to check passive scan queue: %v", err)
			}
			leftStr := fmt.Sprint(rec["recordsToScan"])
			left, err := strconv.Atoi(leftStr)
			if err != nil {
				log.Fatalf("[runZap] failed to parse recordsToScan (%s): %v", leftStr, err)
			}
			log.Printf("[runZap] Passive scanner queue: %d records left", left)
			if left == 0 {
				break
			}
			time.Sleep(2 * time.Second)
		}

		// 3) start active scan for URL
		log.Printf("[runZap] Starting active scan on: %s", target)
		resp, err := ascan.Scan(
			target,
			"false", // no recurse
			"false", // no scope restriction
			"",      // default policy (all rules)
			"",      // any method
			"",      // no post data
			"",      // no context
		)
		if err != nil {
			log.Fatalf("[runZap] failed to start active scan for %s: %v", target, err)
		}

		scanID, ok := resp["scan"].(string)
		if !ok {
			log.Fatalf("[runZap] active scan started but could not get scan id from response: %#v", resp)
		}
		log.Printf("[runZap] Active scan id for %s: %s", target, scanID)

		// 4) get scan status until 100%
		for {
			select {
			case <-ctx.Done():
				log.Printf("[runZap] context cancelled while waiting for active scan (target: %s)", target)
				return
			default:
			}

			statusMap, err := ascan.Status(scanID)
			if err != nil {
				log.Fatalf("[runZap] failed to get ascan status for %s: %v", target, err)
			}
			statusStr := fmt.Sprint(statusMap["status"])
			percent, err := strconv.Atoi(statusStr)
			if err != nil {
				log.Fatalf("[runZap] failed to parse ascan status (%s): %v", statusStr, err)
			}
			log.Printf("[runZap] Active scan progress for %s: %d%%", target, percent)
			if percent >= 100 {
				break
			}
			time.Sleep(2 * time.Second)
		}

		log.Printf("[runZap] Active scan complete for %s", target)
	}

	// generate JSON report
	log.Println("[runZap] Generating ZAP JSON report for all targets...")

	report, err := client.Core().Jsonreport()
	if err != nil {
		log.Fatalf("[runZap] failed to generate ZAP JSON report: %v", err)
	}

	filename := filepath.Join(reportDir, fmt.Sprintf("zap-%d.json", time.Now().Unix()))
	if err := os.WriteFile(filename, report, 0o644); err != nil {
		log.Fatalf("[runZap] failed to write ZAP JSON report file %s: %v", filename, err)
	}

	log.Printf("[runZap] ZAP JSON report saved to %s", filename)
}

// TODO remove fingerprint
func fingerprint(v models.Vulnerability) string {
	log.Printf("[fingerprint] generating fingerprint for tool=%s title=%s url=%s", v.Tool, v.Title, v.URL)

	h := sha1.New()
	h.Write([]byte(v.Tool + "|" + v.Title + "|" + v.URL))
	fp := hex.EncodeToString(h.Sum(nil))

	log.Printf("[fingerprint] result: %s", fp)
	return fp
}
