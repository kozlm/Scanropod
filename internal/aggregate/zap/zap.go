package zap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kozlm/scanropods/internal/cwe"
	"github.com/kozlm/scanropods/internal/helper"
	"github.com/kozlm/scanropods/internal/model"
)

type result struct {
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

var (
	loadZapMap = cwe.LoadZapMap
	readDir    = os.ReadDir
	readFile   = os.ReadFile
	cleanUrl   = helper.CleanUrl
)

// ParseReports reads all ZAP JSON files for given scanID
func ParseReports(scanID, zapCSVPath string) ([]model.NormalizedFinding, error) {
	cweMap, err := loadZapMap(zapCSVPath)
	if err != nil {
		return nil, fmt.Errorf("load zap cwe map: %w", err)
	}

	reportsDir := filepath.Join("reports", scanID)
	entries, err := readDir(reportsDir)
	if err != nil {
		return nil, fmt.Errorf("read reports dir: %w", err)
	}

	var out []model.NormalizedFinding

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isZapReportFile(name) {
			continue
		}

		path := filepath.Join(reportsDir, name)

		fileFindings, err := parseSingleReport(path, cweMap)
		if err != nil {
			return nil, fmt.Errorf("parse zap report %s: %w", name, err)
		}
		out = append(out, fileFindings...)
	}

	return out, nil
}

func isZapReportFile(name string) bool {
	return filepath.Ext(name) == ".json" && strings.HasPrefix(name, "zap-")
}

func parseSingleReport(path string, cweMap cwe.ZapMap) ([]model.NormalizedFinding, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var res result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("unmarshal zap json: %w", err)
	}

	var findings []model.NormalizedFinding

	for _, site := range res.Sites {

		for _, alert := range site.Alerts {
			cweID := cweMap[alert.AlertRef]
			if cweID == "" {
				cweID = "0"
			}

			targetUrl, err := cleanUrl(alert.Instances[0].URI)
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
