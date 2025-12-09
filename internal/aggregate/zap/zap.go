package zap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/helper"
	"github.com/kozlm/scanropods/internal/model"
)

type report struct {
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

type ZapFindingPayload struct {
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

// ParseReports reads all ZAP JSON files for given scanID
func ParseReports(scanID, zapCSVPath string) ([]model.NormalizedFinding, error) {
	zm, err := cwe.LoadZapMap(zapCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load zap cwe map: %w", err)
	}

	reportsDir := filepath.Join("reports", scanID)
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil, fmt.Errorf("read reports dir: %w", err)
	}

	var out []model.NormalizedFinding

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isZapReportFile(name) {
			continue
		}

		path := filepath.Join(reportsDir, name)
		fileFindings, err := parseSingleReport(path, zm)
		if err != nil {
			return nil, fmt.Errorf("parse zap report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

func isZapReportFile(name string) bool {
	return filepath.Ext(name) == ".json" && (name == "zap.json" || len(name) >= 4 && name[:4] == "zap-")
}

func parseSingleReport(path string, zm cwe.ZapMap) ([]model.NormalizedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal zap json: %w", err)
	}

	var findings []model.NormalizedFinding

	for _, s := range r.Sites {

		for _, a := range s.Alerts {
			cweID := zm[a.AlertRef]
			if cweID == "" {
				cweID = "0"
			}

			targetUrl, err := helper.CleanUrl(a.Instances[0].URI)
			if err != nil {
				return nil, fmt.Errorf("clean zap targetUrl: %w", err)
			}

			payload := ZapFindingPayload{
				Alert:      a.Alert,
				Name:       a.Name,
				RiskCode:   a.RiskCode,
				Confidence: a.Confidence,
				Desc:       a.Desc,
				Solution:   a.Solution,
				Reference:  a.Reference,
				Method:     a.Instances[0].Method,
				Param:      a.Instances[0].Param,
				Evidence:   a.Instances[0].Evidence,
				URI:        a.Instances[0].URI,
			}

			findings = append(findings, model.NormalizedFinding{
				TargetURL: targetUrl,
				CWEID:     cweID,
				Scanner:   model.ScannerZap,
				Payload:   payload,
			})
		}
	}

	return findings, nil
}
