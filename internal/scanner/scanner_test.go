package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kozlm/scanropod/internal/model"
)

var (
	defaultUUID        = newUUID
	defaultEnsureDir   = ensureDir
	defaultRun         = runScanner
	defaultSetStatus   = setStatus
	defaultSetResult   = setResult
	defaultExecCommand = execCommandContext
	defaultWrite       = writeFile
	defaultStat        = statFile
)

func cleanup(t *testing.T) {
	t.Cleanup(func() {
		newUUID = defaultUUID
		ensureDir = defaultEnsureDir
		runScanner = defaultRun
		setStatus = defaultSetStatus
		setResult = defaultSetResult
		execCommandContext = defaultExecCommand
		writeFile = defaultWrite
		statFile = defaultStat

		activeCancel.Lock()
		activeCancel.cancelMap = make(map[string]context.CancelFunc)
		activeCancel.Unlock()
	})
}

func TestInitSetsPaths(t *testing.T) {
	Init("/base")

	if baseReportsDir == "" || baseOutputsDir == "" {
		t.Fatal("base dirs not initialized")
	}

	if nucleiConfigPath == "" || zapConfigPath == "" {
		t.Fatal("config paths not initialized")
	}
}

func TestStartScanDone(t *testing.T) {
	cleanup(t)

	statuses := make(chan model.ScanStatus, 2)

	newUUID = func() string { return "scan-1" }
	ensureDir = func(string) {}

	runScans = func(ctx context.Context, scanners []string, targets []string) model.ScanStatus {
		return model.StatusDone
	}

	setStatus = func(_ string, res model.ScanResult) {
		statuses <- res.Status
	}
	setResult = func(_ string, res model.ScanResult) {
		statuses <- res.Status
	}

	Init("/base")

	_, err := StartScan(&model.ScanRequest{
		Targets:  []string{"http://example.com"},
		Scanners: []string{"nikto"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if <-statuses != model.StatusRunning {
		t.Fatal("expected RUNNING")
	}
	if <-statuses != model.StatusDone {
		t.Fatal("expected DONE")
	}
}

func TestStartScanFailed(t *testing.T) {
	cleanup(t)

	statuses := make(chan model.ScanStatus, 2)

	newUUID = func() string { return "scan-2" }
	ensureDir = func(string) {}

	runScans = func(ctx context.Context, scanners []string, targets []string) model.ScanStatus {
		return model.StatusFailed
	}

	setStatus = func(_ string, res model.ScanResult) {
		statuses <- res.Status
	}
	setResult = func(_ string, res model.ScanResult) {
		statuses <- res.Status
	}

	Init("/base")

	_, err := StartScan(&model.ScanRequest{
		Targets:  []string{"http://example.com"},
		Scanners: []string{"nikto"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if <-statuses != model.StatusRunning {
		t.Fatal("expected RUNNING")
	}
	if <-statuses != model.StatusFailed {
		t.Fatal("expected FAILED")
	}
}

func TestRunScansOnTargetsDone(t *testing.T) {
	runScanner = func(ctx context.Context, name string, targets []string) error {
		return nil
	}

	status := runScansOnTargets(
		context.Background(),
		[]string{"nikto", "zap"},
		[]string{"http://example.com"},
	)

	if status != model.StatusDone {
		t.Fatalf("expected DONE, got %v", status)
	}
}

func TestRunScansOnTargetsFailed(t *testing.T) {
	runScanner = func(ctx context.Context, name string, targets []string) error {
		if name == "nikto" {
			return errors.New("error")
		}
		return nil
	}

	status := runScansOnTargets(
		context.Background(),
		[]string{"nikto", "zap"},
		[]string{"http://example.com"},
	)

	if status != model.StatusFailed {
		t.Fatalf("expected FAILED, got %v", status)
	}
}

func TestStopScanSuccess(t *testing.T) {
	cleanup(t)

	cancelCalled := false

	activeCancel.Lock()
	activeCancel.cancelMap["scan-3"] = func() {
		cancelCalled = true
	}
	activeCancel.Unlock()

	err := StopScan("scan-3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cancelCalled {
		t.Fatal("expected cancel func to be called")
	}

	activeCancel.Lock()
	if _, ok := activeCancel.cancelMap["scan-3"]; ok {
		activeCancel.Unlock()
		t.Fatal("expected scan to be removed from cancelMap")
	}
	activeCancel.Unlock()
}

func TestStopScanInvalidID(t *testing.T) {
	if err := StopScan("does-not-exist"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunSingleScanner(t *testing.T) {
	cleanup(t)

	execCalled := 0
	writeCalled := 0
	statCalled := 0

	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		execCalled++

		if name != "nikto" {
			t.Fatalf("unexpected command: %s", name)
		}

		return exec.CommandContext(ctx, "true")
	}

	writeFile = func(path string, data []byte, perm os.FileMode) error {
		writeCalled++

		if !strings.Contains(path, "nikto-") {
			t.Fatalf("unexpected output path: %s", path)
		}
		return nil
	}

	statFile = func(path string) (os.FileInfo, error) {
		statCalled++

		if !strings.Contains(path, "nikto-") {
			t.Fatalf("unexpected report path: %s", path)
		}
		return fakeFileInfo{}, nil
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, reportsDirCtxKey, "/reports")
	ctx = context.WithValue(ctx, outputsDirCtxKey, "/outputs")

	err := runSingleScanner(
		ctx,
		"nikto",
		[]string{"http://example.com"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if execCalled != 1 {
		t.Fatalf("expected exec to be called once, called %d times", execCalled)
	}

	if writeCalled != 1 {
		t.Fatalf("expected writeFile to be called once, called %d times", writeCalled)
	}

	if statCalled != 1 {
		t.Fatalf("expected statFile to be called once, called %d times", statCalled)
	}
}

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "file" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
