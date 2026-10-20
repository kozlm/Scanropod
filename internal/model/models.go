// Package model holds the data types of the Scanropod API contract:
// scan requests, scan status/results, and the aggregated report. These
// types are shared across the API, scanner, and report packages.
package model

import "time"

type ScanRequest struct {
	Targets  []string               `json:"targets" binding:"required"`
	Scanners []string               `json:"scanners"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

type ScanResult struct {
	ID         string     `json:"id"`
	Targets    []string   `json:"targets"`
	Scanners   []string   `json:"scanners"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     ScanStatus `json:"status"`

	Result *AggregatedReport `json:"result,omitempty"`
}

type ScannerName string

const (
	ScannerNuclei ScannerName = "nuclei"
	ScannerNikto  ScannerName = "nikto"
	ScannerZap    ScannerName = "zap"
	ScannerWapiti ScannerName = "wapiti"
)

type ScanStatus string

const (
	StatusRunning ScanStatus = "running"
	StatusDone    ScanStatus = "done"
	StatusFailed  ScanStatus = "failed"
	StatusStopped ScanStatus = "stopped"
)

type AggregatedReport struct {
	ScanDate time.Time                                           `json:"scan_date"`
	Findings map[string]map[string]map[ScannerName][]interface{} `json:"findings"`
}
