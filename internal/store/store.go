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

func SetStatus(id string, result model.ScanResult) {
	mu.Lock()
	defer mu.Unlock()
	statuses[id] = result
}

func GetStatus(id string) (model.ScanResult, bool) {
	mu.RLock()
	defer mu.RUnlock()
	status, ok := statuses[id]
	return status, ok
}

func SetResult(id string, result model.ScanResult) {
	mu.Lock()
	defer mu.Unlock()
	results[id] = result
}

func GetResult(id string) (model.ScanResult, bool) {
	mu.RLock()
	defer mu.RUnlock()
	result, ok := results[id]
	return result, ok
}
