package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScannerCommandArguments locks in the exact command line produced
// for each external scanner for a single target.
func TestScannerCommandArguments(t *testing.T) {
	cleanup(t)
	Init("/base")

	target := "http://example.com"
	ctx := context.Background()
	ctx = context.WithValue(ctx, reportsDirCtxKey, "/reports")
	ctx = context.WithValue(ctx, outputsDirCtxKey, "/outputs")

	var gotName string
	var gotArgs []string

	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = args
		return exec.CommandContext(ctx, "true")
	}

	stubOutputWrites(t)

	runScanner := func(scannerName string) {
		t.Helper()

		gotName, gotArgs = "", nil

		if err := runSingleScanner(ctx, scannerName, []string{target}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	t.Run("nikto", func(t *testing.T) {
		runScanner("nikto")

		if gotName != "nikto" {
			t.Fatalf("unexpected command: %s", gotName)
		}

		reportFile := reportArg(t, gotArgs, "-o")
		expectReportPath(t, reportFile, "/reports", "nikto")

		want := []string{
			"-h", target,
			"-Tuning", "x6abd",
			"-Plugins", strings.Join(niktoPlugins, ";"),
			"-ask", "no",
			"-nointeractive",
			"-o", reportFile,
			"-Format", "json",
		}
		if !equalStrings(gotArgs, want) {
			t.Fatalf("unexpected args:\ngot:  %v\nwant: %v", gotArgs, want)
		}
	})

	t.Run("nuclei", func(t *testing.T) {
		runScanner("nuclei")

		if gotName != "nuclei" {
			t.Fatalf("unexpected command: %s", gotName)
		}

		reportFile := reportArg(t, gotArgs, "-json-export")
		expectReportPath(t, reportFile, "/reports", "nuclei")

		want := []string{
			"-u", target,
			"-duc",
			"-ni",
			"-config", "/base/config/nuclei/nuclei-config.yaml",
			"-json-export", reportFile,
		}
		if !equalStrings(gotArgs, want) {
			t.Fatalf("unexpected args:\ngot:  %v\nwant: %v", gotArgs, want)
		}
	})

	t.Run("wapiti", func(t *testing.T) {
		runScanner("wapiti")

		if gotName != "wapiti" {
			t.Fatalf("unexpected command: %s", gotName)
		}

		reportFile := reportArg(t, gotArgs, "-o")
		expectReportPath(t, reportFile, "/reports", "wapiti")

		want := []string{
			"--flush-session",
			"-m", strings.Join(wapitiModules, ","),
			"-u", target,
			"--scope", "page",
			"-f", "json",
			"-o", reportFile,
		}
		if !equalStrings(gotArgs, want) {
			t.Fatalf("unexpected args:\ngot:  %v\nwant: %v", gotArgs, want)
		}
	})

	t.Run("zap", func(t *testing.T) {
		runScanner("zap")

		if gotName != "zap" {
			t.Fatalf("unexpected command: %s", gotName)
		}

		want := []string{
			"-cmd",
			"-autorun", "/base/config/zap/zap-config.yaml",
		}
		if !equalStrings(gotArgs, want) {
			t.Fatalf("unexpected args:\ngot:  %v\nwant: %v", gotArgs, want)
		}
	})
}

// TestZapCommandEnvironment locks in the SCANROPOD_* environment passed
// to the ZAP autorun script.
func TestZapCommandEnvironment(t *testing.T) {
	target := "http://example.com"
	reportFile := "/reports/zap-http_example.com_1700000000.json"

	cmd := zapCommand(context.Background(), target, "/reports", reportFile)

	envMap := envAsMap(t, cmd.Env)

	if envMap["SCANROPOD_TARGET_URL"] != target {
		t.Fatalf("unexpected SCANROPOD_TARGET_URL: %q", envMap["SCANROPOD_TARGET_URL"])
	}
	if envMap["SCANROPOD_REPORT_DIR"] != "/reports" {
		t.Fatalf("unexpected SCANROPOD_REPORT_DIR: %q", envMap["SCANROPOD_REPORT_DIR"])
	}
	if envMap["SCANROPOD_REPORT_FILE"] != filepath.Base(reportFile) {
		t.Fatalf("unexpected SCANROPOD_REPORT_FILE: %q", envMap["SCANROPOD_REPORT_FILE"])
	}

	// the parent environment must be preserved
	envSet := make(map[string]bool)
	for _, entry := range cmd.Env {
		envSet[entry] = true
	}
	for _, entry := range os.Environ() {
		if !envSet[entry] {
			if key, _, _ := strings.Cut(entry, "="); key == "SCANROPOD_TARGET_URL" ||
				key == "SCANROPOD_REPORT_DIR" || key == "SCANROPOD_REPORT_FILE" {
				continue // overridden by zapCommand
			}
			t.Fatalf("expected parent environment to be preserved, missing %q", entry)
		}
	}
}

func stubOutputWrites(t *testing.T) {
	t.Helper()

	writeFile = func(string, []byte, os.FileMode) error {
		return nil
	}

	statFile = func(string) (os.FileInfo, error) {
		return fakeFileInfo{}, nil
	}
}

func expectReportPath(t *testing.T, reportFile, dir, scannerName string) {
	t.Helper()

	prefix := dir + "/" + scannerName + "-http_example.com-"
	if !strings.HasPrefix(reportFile, prefix) || !strings.HasSuffix(reportFile, ".json") {
		t.Fatalf("unexpected report file: %s", reportFile)
	}
}

func reportArg(t *testing.T, args []string, flag string) string {
	t.Helper()

	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("flag %s not found in %v", flag, args)
	return ""
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func envAsMap(t *testing.T, env []string) map[string]string {
	t.Helper()

	out := make(map[string]string)
	for _, entry := range env {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("malformed env entry: %q", entry)
		}
		out[key] = value
	}
	return out
}
