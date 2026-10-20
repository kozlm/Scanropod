package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/kozlm/scanropod/internal/model"
)

// parseZapReports reads all ZAP JSON files for given scanID
func parseZapReports(scanID, zapCSVPath string) ([]normalizedFinding, error) {
	cweIDMap, err := loadZapMap(zapCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load zap cwe map: %w", err)
	}

	paths, err := collectReportFiles(scanID, "zap-")
	if err != nil {
		return nil, err
	}

	var out []normalizedFinding
	for _, path := range paths {
		name := filepath.Base(path)
		fileFindings, err := parseZapFile(path, cweIDMap)
		if err != nil {
			return nil, fmt.Errorf("parse zap report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

type zapReport struct {
	Created string    `json:"created"`
	Sites   []zapSite `json:"site"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Host   string     `json:"@host"`
	Port   string     `json:"@port"`
	SSL    string     `json:"@ssl"`
	Alerts []zapAlert `json:"alerts"`
}

type zapAlert struct {
	PluginID   string        `json:"pluginid"`
	AlertRef   string        `json:"alertRef"`
	Alert      string        `json:"alert"`
	Name       string        `json:"name"`
	RiskCode   string        `json:"riskcode"`
	Confidence string        `json:"confidence"`
	RiskDesc   string        `json:"riskdesc"`
	Desc       string        `json:"desc"`
	Solution   string        `json:"solution"`
	Reference  string        `json:"reference"`
	CWEID      string        `json:"cweid"`
	Instances  []zapInstance `json:"instances"`
}

type zapInstance struct {
	ID       string `json:"id"`
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
}

type zapFindingPayload struct {
	Alert      string `json:"alert"`
	Name       string `json:"name"`
	RiskCode   string `json:"riskcode"`
	Confidence string `json:"confidence"`
	Desc       string `json:"desc"`
	Solution   string `json:"solution"`
	Reference  string `json:"reference"`
	Method     string `json:"method"`
	Param      string `json:"param"`
	Evidence   string `json:"evidence"`
	URI        string `json:"uri"`
}

var loadZapMap = func(path string) (cweMap, error) {
	return loadMap(path, "zap")
}

func parseZapFile(path string, cweIDMap cweMap) ([]normalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var res zapReport
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("unmarshal zap json: %w", err)
	}

	var findings []normalizedFinding

	for _, site := range res.Sites {

		for _, alert := range site.Alerts {
			cweID := cweIDMap[alert.AlertRef]
			if cweID == "" {
				cweID = "0"
			}

			targetUrl, err := cleanURL(alert.Instances[0].URI)
			if err != nil {
				return nil, fmt.Errorf("clean zap targetUrl: %w", err)
			}

			payload := zapFindingPayload{
				Alert:      alert.Alert,
				Name:       alert.Name,
				RiskCode:   alert.RiskCode,
				Confidence: alert.Confidence,
				Desc:       alert.Desc,
				Solution:   alert.Solution,
				Reference:  alert.Reference,
				Method:     alert.Instances[0].Method,
				Param:      alert.Instances[0].Param,
				Evidence:   alert.Instances[0].Evidence,
				URI:        alert.Instances[0].URI,
			}

			findings = append(findings, normalizedFinding{
				TargetURL: targetUrl,
				CWEID:     cweID,
				Scanner:   model.ScannerZap,
				Payload:   payload,
			})
		}
	}

	return findings, nil
}
