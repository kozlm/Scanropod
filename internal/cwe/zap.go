package cwe

import (
	"encoding/csv"
	"errors"
	"log"
	"os"
	"strings"
)

type ZapMap map[string]string // alert_id -> CWE

func LoadZapMap(path string) (ZapMap, error) {
	// CSV columns: id,cwe
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[LoadZapMap] open zap map '%s': %v", path, err)
		return nil, errors.New("failed to read zap map file")
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		log.Printf("[LoadZapMap] parse zap csv: %v", err)
		return nil, errors.New("failed to parse zap csv")
	}

	out := make(ZapMap)
	for _, record := range records[1:] {
		if len(record) < 2 {
			continue
		}
		alertId := strings.TrimSpace(record[0])
		cwe := strings.TrimSpace(record[1])
		if alertId == "" {
			continue
		}
		out[alertId] = cwe
	}
	return out, nil
}
