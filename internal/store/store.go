package store

import (
	"sync"
	"time"

	"github.com/kozlm/scanropods/internal/models"
)

var (
	mu       sync.RWMutex
	statuses map[string]models.ScanResult
	results  map[string]models.ScanResult
)

func Init() {
	mu.Lock()
	defer mu.Unlock()
	statuses = make(map[string]models.ScanResult)
	results = make(map[string]models.ScanResult)
}

func SetStatus(id string, s models.ScanResult) {
	mu.Lock()
	defer mu.Unlock()
	statuses[id] = s
}

func GetStatus(id string) (models.ScanResult, bool) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := statuses[id]
	return s, ok
}

func SetResult(id string, r models.ScanResult) {
	mu.Lock()
	defer mu.Unlock()
	results[id] = r
}

func GetResult(id string) (models.ScanResult, bool) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := results[id]
	return r, ok
}

func MarkFinished(id string) {
	mu.Lock()
	defer mu.Unlock()
	r := results[id]
	now := time.Now()
	r.FinishedAt = &now
	results[id] = r
}
