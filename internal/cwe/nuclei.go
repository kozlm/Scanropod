package cwe

import (
	"encoding/csv"
	"errors"
	"log"
	"os"
	"strings"
)

type NucleiMap map[string]string // id -> CWE

func LoadNucleiMap(path string) (NucleiMap, error) {
	// CSV columns: id,cwe
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[LoadNucleiMap] open nuclei map '%s': %v", path, err)
		return nil, errors.New("failed to read nuclei map file")
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		log.Printf("[LoadNucleiMap] parse nuclei csv: %v", err)
		return nil, errors.New("failed to parse nuclei csv")
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
