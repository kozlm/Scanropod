package models

import "time"

type ScanRequest struct {
	Targets  []string               `json:"targets" binding:"required"`
	Scanners []string               `json:"scanners"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

type Vulnerability struct {
	Tool     string `json:"tool"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Details  string `json:"details,omitempty"`
}

type ScanResult struct {
	ID              string          `json:"id"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
