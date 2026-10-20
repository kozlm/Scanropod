package server

import (
	"testing"

	"github.com/kozlm/scanropod/internal/model"
)

func TestValidateScanRequestNil(t *testing.T) {
	if err := validateScanRequest(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestEmptyTargets(t *testing.T) {
	req := &model.ScanRequest{}
	if err := validateScanRequest(req); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestInvalidTarget(t *testing.T) {
	req := &model.ScanRequest{
		Targets: []string{"ftp://example.com"},
	}

	if err := validateScanRequest(req); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestValid(t *testing.T) {
	req := &model.ScanRequest{
		Targets:  []string{"http://example.com"},
		Scanners: []string{"Zap", "nikto", "zap"},
	}

	err := validateScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(req.Scanners) != 2 {
		t.Fatalf("expected 2 scanners, got %d", len(req.Scanners))
	}
}

func TestValidateScanRequestUnsupportedScanner(t *testing.T) {
	req := &model.ScanRequest{
		Targets:  []string{"http://example.com"},
		Scanners: []string{"nikto", "unknown"},
	}

	if err := validateScanRequest(req); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateScanRequestNoScanners(t *testing.T) {
	req := &model.ScanRequest{
		Targets: []string{"http://example.com"},
	}

	if err := validateScanRequest(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(req.Scanners) != 0 {
		t.Fatalf("expected empty scanners, got %v", req.Scanners)
	}
}
