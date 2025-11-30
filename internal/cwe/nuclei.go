package cwe

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

type NucleiMap map[string]string // id -> CWE

func LoadNucleiMap(path string) (NucleiMap, error) {
	// CSV columns: id,cwe
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read nuclei map file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse nuclei csv: %w", err)
	}

	out := make(NucleiMap)
	for _, record := range records[1:] {
		if len(record) < 2 {
			continue
		}
		id := strings.TrimSpace(record[0])
		cwe := strings.TrimSpace(record[1])
		if id == "" {
			continue
		}
		out[id] = cwe
	}
	return out, nil
}
