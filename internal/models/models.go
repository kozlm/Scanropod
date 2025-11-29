package models

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
	Done       bool       `json:"done"`

	Result *AggregatedReport `json:"result,omitempty"`
}
