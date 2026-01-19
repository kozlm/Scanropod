package aggregate

import (
	"time"

	"github.com/kozlm/scanropod/internal/aggregate/nikto"
	"github.com/kozlm/scanropod/internal/aggregate/nuclei"
	"github.com/kozlm/scanropod/internal/aggregate/wapiti"
	"github.com/kozlm/scanropod/internal/aggregate/zap"
	"github.com/kozlm/scanropod/internal/model"
)

type BuilderConfig struct {
	ZapCSVPath    string
	WapitiCSVPath string
	NiktoCSVPath  string
	NucleiCSVPath string
}

// Build builds the final AggregatedReport for given scanID.
func Build(scanID string, cfg BuilderConfig) (model.AggregatedReport, error) {
	var all []model.NormalizedFinding

	// ZAP
	if cfg.ZapCSVPath != "" {
		zapFindings, err := zap.ParseReports(scanID, cfg.ZapCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, zapFindings...)
	}

	// Wapiti
	if cfg.WapitiCSVPath != "" {
		wapitiFindings, err := wapiti.ParseReports(scanID, cfg.WapitiCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, wapitiFindings...)
	}

	// Nikto
	if cfg.NiktoCSVPath != "" {
		niktoFindings, err := nikto.ParseReports(scanID, cfg.NiktoCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, niktoFindings...)
	}

	// Nuclei
	if cfg.NucleiCSVPath != "" {
		nucleiFindings, err := nuclei.ParseReports(scanID, cfg.NucleiCSVPath)
		if err != nil {
			return model.AggregatedReport{}, err
		}
		all = append(all, nucleiFindings...)
	}

	return groupFindings(all), nil
}

func groupFindings(rawFindings []model.NormalizedFinding) model.AggregatedReport {
	// map[target][cwe][scanner] -> []payload

	byTarget := make(map[string]map[string]map[model.ScannerName][]interface{})

	for _, finding := range rawFindings {
		if finding.TargetURL == "" {
			finding.TargetURL = "unknown"
		}
		if byTarget[finding.TargetURL] == nil {
			byTarget[finding.TargetURL] = make(map[string]map[model.ScannerName][]interface{})
		}
		if byTarget[finding.TargetURL][finding.CWEID] == nil {
			byTarget[finding.TargetURL][finding.CWEID] = make(map[model.ScannerName][]interface{})
		}
		byTarget[finding.TargetURL][finding.CWEID][finding.Scanner] =
			append(byTarget[finding.TargetURL][finding.CWEID][finding.Scanner], finding.Payload)
	}

	return model.AggregatedReport{
		ScanDate: time.Now().UTC(),
		Findings: byTarget,
	}
}
