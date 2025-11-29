package cwe

import (
	"encoding/csv"
	"errors"
	"log"
	"os"
	"strings"
)

type NiktoMap map[string]string // id -> CWE

func LoadNiktoMap(path string) (NiktoMap, error) {
	// CSV columns: id,cwe
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[LoadNiktoMap] open nikto map '%s': %v", path, err)
		return nil, errors.New("failed to read nikto map file")
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		log.Printf("[LoadNiktoMap] parse nikto csv: %v", err)
		return nil, errors.New("failed to parse nikto csv")
	}

	out := make(NiktoMap)
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
