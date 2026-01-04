package server

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kozlm/scanropods/internal/aggregate"
	"github.com/kozlm/scanropods/internal/helper"
	"github.com/kozlm/scanropods/internal/model"
	"github.com/kozlm/scanropods/internal/scanner"
	"github.com/kozlm/scanropods/internal/store"
)

var baseDir string

func Run() error {
	store.Init()
	log.Println("[server] store initialized")

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal("[server] could not get working directory")
	}
	log.Printf("[server] base dir: %s", dir)
	baseDir = dir

	scanner.Init(baseDir)

	r := gin.Default()

	r.POST("/scan/start", startHandler)
	r.GET("/scan/status/:id", statusHandler)
	r.GET("/scan/result/:id", resultHandler)
	r.POST("/scan/stop/:id", stopHandler)

	server := &http.Server{
		Addr:           ":8000",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   0,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	log.Printf("[server] listening on %s", server.Addr)
	return server.ListenAndServe()
}

func startHandler(ctx *gin.Context) {
	var request scanner.ScanRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		log.Printf("[startHandler] invalid request: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := helper.ValidateScanRequest(&request); err != nil {
		log.Printf("[startHandler] invalid request: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[startHandler] starting scan for targets: %v, scanners: %v", request.Targets, request.Scanners)

	id, err := scanner.StartScan(&request)
	if err != nil {
		log.Printf("[startHandler] StartScan error: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start scan"})
		return
	}

	log.Printf("[startHandler] scan started, id=%s", id)
	ctx.JSON(http.StatusAccepted, gin.H{"scan_id": id})
}

func statusHandler(ctx *gin.Context) {
	id := ctx.Param("id")
	log.Printf("[statusHandler] checking status for id=%s", id)

	status, ok := store.GetStatus(id)
	if !ok {
		log.Printf("[statusHandler] status not found for id=%s", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	ctx.JSON(http.StatusOK, status)
}

func resultHandler(ctx *gin.Context) {
	id := ctx.Param("id")
	log.Printf("[resultHandler] fetching result for id=%s", id)

	status, ok := store.GetStatus(id)
	if !ok {
		log.Printf("[resultHandler] status not found for id=%s", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	if status.Status != model.StatusDone {
		log.Printf("[resultHandler] scan not ready for id=%s", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "scan not ready"})
		return
	}

	if status.Status == model.StatusFailed {
		log.Printf("[resultHandler] scan failed for id=%s", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "scan failed"})
		return
	}

	// if result built, reuse it
	if result, ok := store.GetResult(id); ok && result.Result != nil {
		ctx.JSON(http.StatusOK, result)
		return
	}

	aggregated, err := aggregate.Build(id, aggregate.BuilderConfig{
		ZapCSVPath:    filepath.Join(baseDir, "config/cwe-lists/zap-csv-fix.csv"),
		WapitiCSVPath: filepath.Join(baseDir, "config/cwe-lists/wapiti-csv.csv"),
		NiktoCSVPath:  filepath.Join(baseDir, "config/cwe-lists/nikto-csv-fix.csv"),
		NucleiCSVPath: filepath.Join(baseDir, "config/cwe-lists/nuclei-csv.csv"),
	})
	if err != nil {
		log.Printf("[resultHandler] build aggregated report id=%s: %v", id, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}

	result := status
	result.Result = &aggregated
	store.SetResult(id, result)

	ctx.JSON(http.StatusOK, result)
}

func stopHandler(ctx *gin.Context) {
	id := ctx.Param("id")
	log.Printf("[stopHandler] stopping scan id=%s", id)

	status, ok := store.GetStatus(id)
	if !ok {
		log.Printf("[stopHandler] status not found for id=%s", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	if err := scanner.StopScan(id); err != nil {
		log.Printf("[stopHandler] scan already finished with id=%s", id)
		ctx.JSON(http.StatusConflict, gin.H{"error": "scan already finished"})
		return
	}
	log.Printf("[stopHandler] stop signal sent for id=%s", id)

	status.Status = model.StatusStopped
	store.SetStatus(id, status)
	ctx.JSON(http.StatusOK, status)
}
