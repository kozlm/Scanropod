package models

import "time"

type ScannerName string

const (
	ScannerNuclei ScannerName = "nuclei"
	ScannerNikto  ScannerName = "nikto"
	ScannerZap    ScannerName = "zap"
	ScannerWapiti ScannerName = "wapiti"
)

type AggregatedReport struct {
	ScanDate time.Time     `json:"scan_date"`
	Targets  []TargetEntry `json:"targets"`
}

type TargetEntry struct {
	URL  string     `json:"url"`
	CWEs []CWEEntry `json:"cwes"`
}

type CWEEntry struct {
	CWEID    string         `json:"cwe_id"`
	Scanners []ScannerEntry `json:"scanners"`
}

type ScannerEntry struct {
	Name     ScannerName   `json:"name"`
	Findings []interface{} `json:"findings"`
}

// Normalized "atom" that parsers will return,
// then we group them into the structure above.
type NormalizedFinding struct {
	TargetURL string      // e.g. "http://192.168.0.156"
	CWEID     string      // "CWE-79", "0" for informational
	Scanner   ScannerName // zap/wapiti/...
	Payload   interface{} // concrete struct per scanner
}
