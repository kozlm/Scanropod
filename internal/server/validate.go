package server

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/kozlm/scanropod/internal/model"
)

func validateScanRequest(req *model.ScanRequest) error {
	if req == nil || len(req.Targets) == 0 {
		return errors.New("targets list is empty")
	}

	for _, target := range req.Targets {
		if !isValidTarget(target) {
			return fmt.Errorf("invalid target: %s", target)
		}
	}

	scanners, err := validateScanners(req.Scanners)
	if err != nil {
		return err
	}
	req.Scanners = scanners

	return nil
}

func isValidTarget(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	return true
}

func validateScanners(scanners []string) ([]string, error) {
	allowedScanners := []string{"nikto", "nuclei", "wapiti", "zap"}
	if len(scanners) == 0 {
		return []string{}, nil
	}

	seen := make(map[string]struct{})
	var normalized []string

	for _, scanner := range scanners {
		scanner = strings.ToLower(strings.TrimSpace(scanner))

		if !slices.Contains(allowedScanners, scanner) {
			return nil, fmt.Errorf("unsupported scanner: %s", scanner)
		}

		if _, exists := seen[scanner]; !exists {
			seen[scanner] = struct{}{}
			normalized = append(normalized, scanner)
		}
	}

	return normalized, nil
}
