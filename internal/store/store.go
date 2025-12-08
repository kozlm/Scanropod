package store

import (
	"sync"

	"github.com/kozlm/scanropods/internal/model"
)

var (
	mu       sync.RWMutex
	statuses map[string]model.ScanResult
	results  map[string]model.ScanResult
)

func Init() {
	mu.Lock()
	defer mu.Unlock()
	statuses = make(map[string]model.ScanResult)
	results = make(map[string]model.ScanResult)
}

func SetStatus(id string, s model.ScanResult) {
	mu.Lock()
	defer mu.Unlock()
	statuses[id] = s
}

func GetStatus(id string) (model.ScanResult, bool) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := statuses[id]
	return s, ok
}

func SetResult(id string, r model.ScanResult) {
	mu.Lock()
	defer mu.Unlock()
	results[id] = r
}

func GetResult(id string) (model.ScanResult, bool) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := results[id]
	return r, ok
}
