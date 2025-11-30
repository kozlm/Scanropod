package cwe

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

type WapitiMap struct {
	byName      map[string]string  // for rows with no keyphrase
	tlsByPhrase []tlsPhraseMapping // for TLS/SSL misconfigurations rows
}

type tlsPhraseMapping struct {
	Phrase string
	CWE    string
}

func LoadWapitiMap(path string) (*WapitiMap, error) {
	// CSV columns: name,cwe,keyphrase
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read wapiti map file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse wapiti csv: %w", err)
	}

	m := &WapitiMap{
		byName:      make(map[string]string),
		tlsByPhrase: []tlsPhraseMapping{},
	}

	for _, record := range records[1:] {
		if len(record) < 3 {
			continue
		}
		name := strings.TrimSpace(record[0])
		cwe := strings.TrimSpace(record[1])
		phrase := strings.TrimSpace(record[2])
		if name == "" {
			continue
		}
		if strings.EqualFold(name, "TLS/SSL misconfigurations") && phrase != "" {
			m.tlsByPhrase = append(m.tlsByPhrase, tlsPhraseMapping{
				Phrase: phrase,
				CWE:    cwe,
			})
			continue
		}

		// no keyphrase
		if phrase == "" {
			m.byName[name] = cwe
		}
	}

	return m, nil
}

// Lookup returns CWE for given vulnerability name and info
// - for TLS/SSL misconfigurations, tries matching info with keyphrase
// - else, tries matching vulnerability name
// - returns "0" (informational) if no CWE found
func (m *WapitiMap) Lookup(name, info string) string {
	if m == nil {
		return "0"
	}

	nameTrimmed := strings.TrimSpace(name)
	if strings.EqualFold(nameTrimmed, "TLS/SSL misconfigurations") {
		infoLower := strings.ToLower(info)
		for _, e := range m.tlsByPhrase {
			if strings.Contains(infoLower, strings.ToLower(e.Phrase)) {
				return e.CWE
			}
		}
	}

	if cwe, ok := m.byName[nameTrimmed]; ok {
		return cwe
	}
	return "0"
}
