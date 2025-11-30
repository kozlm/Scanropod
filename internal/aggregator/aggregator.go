package aggregator

import (
	"time"

	"github.com/kozlm/scanropods/internal/models"
	"github.com/kozlm/scanropods/internal/scanner/nikto"
	"github.com/kozlm/scanropods/internal/scanner/nuclei"
	"github.com/kozlm/scanropods/internal/scanner/wapiti"
	"github.com/kozlm/scanropods/internal/scanner/zap"
)

type BuilderConfig struct {
	ZapCSVPath    string
	WapitiCSVPath string
	NiktoCSVPath  string
	NucleiCSVPath string
}

// Build builds the final AggregatedReport for given scanID.
func Build(scanID string, cfg BuilderConfig) (models.AggregatedReport, error) {
	var all []models.NormalizedFinding

	// ZAP
	if cfg.ZapCSVPath != "" {
		zapFindings, err := zap.ParseReports(scanID, cfg.ZapCSVPath)
		if err != nil {
			return models.AggregatedReport{}, err
		}
		all = append(all, zapFindings...)
	}

	// Wapiti
	if cfg.WapitiCSVPath != "" {
		wapitiFindings, err := wapiti.ParseReports(scanID, cfg.WapitiCSVPath)
		if err != nil {
			return models.AggregatedReport{}, err
		}
		all = append(all, wapitiFindings...)
	}

	// Nikto
	if cfg.NiktoCSVPath != "" {
		niktoFindings, err := nikto.ParseReports(scanID, cfg.NiktoCSVPath)
		if err != nil {
			return models.AggregatedReport{}, err
		}
		all = append(all, niktoFindings...)
	}

	// Nuclei
	if cfg.NucleiCSVPath != "" {
		nucleiFindings, err := nuclei.ParseReports(scanID, cfg.NucleiCSVPath)
		if err != nil {
			return models.AggregatedReport{}, err
		}
		all = append(all, nucleiFindings...)
	}

	return groupFindings(all), nil
}

func groupFindings(all []models.NormalizedFinding) models.AggregatedReport {
	// map[target][cwe][scanner] -> []payload
	type scannerKey struct {
		target string
		cwe    string
		scan   models.ScannerName
	}

	byTarget := make(map[string]map[string]map[models.ScannerName][]interface{})

	for _, f := range all {
		if f.TargetURL == "" {
			f.TargetURL = "unknown"
		}
		if byTarget[f.TargetURL] == nil {
			byTarget[f.TargetURL] = make(map[string]map[models.ScannerName][]interface{})
		}
		if byTarget[f.TargetURL][f.CWEID] == nil {
			byTarget[f.TargetURL][f.CWEID] = make(map[models.ScannerName][]interface{})
		}
		byTarget[f.TargetURL][f.CWEID][f.Scanner] =
			append(byTarget[f.TargetURL][f.CWEID][f.Scanner], f.Payload)
	}

	var targets []models.TargetEntry
	for url, cweMap := range byTarget {
		var cwes []models.CWEEntry
		for cweID, scannerMap := range cweMap {
			var scanners []models.ScannerEntry
			for scannerName, payloads := range scannerMap {
				scanners = append(scanners, models.ScannerEntry{
					Name:     scannerName,
					Findings: payloads,
				})
			}
			cwes = append(cwes, models.CWEEntry{
				CWEID:    cweID,
				Scanners: scanners,
			})
		}
		targets = append(targets, models.TargetEntry{
			URL:  url,
			CWEs: cwes,
		})
	}

	return models.AggregatedReport{
		ScanDate: time.Now().UTC(),
		Targets:  targets,
	}
}
