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

type NormalizedFinding struct {
	TargetURL string      // e.g. "http://192.168.0.156"
	CWEID     string      // "CWE-79", "0" for informational
	Scanner   ScannerName // zap/wapiti/...
	Payload   interface{} // concrete struct per scanner
}
