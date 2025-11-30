package server

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kozlm/scanropods/internal/aggregator"
	"github.com/kozlm/scanropods/internal/scanner"
	"github.com/kozlm/scanropods/internal/store"
)

func Run() error {
	store.Init()
	log.Println("[server] store initialized")

	r := gin.Default()

	r.POST("/scan/start", startHandler)
	r.GET("/scan/status/:id", statusHandler)
	r.GET("/scan/result/:id", resultHandler)
	r.POST("/scan/stop/:id", stopHandler)

	srv := &http.Server{
		Addr:           ":8000",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   0,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	log.Printf("[server] listening on %s", srv.Addr)
	return srv.ListenAndServe()
}

func startHandler(c *gin.Context) {
	var req scanner.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[startHandler] invalid request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[startHandler] starting scan for targets: %v, scanners: %v", req.Targets, req.Scanners)

	id, err := scanner.StartScan(&req)
	if err != nil {
		log.Printf("[startHandler] StartScan error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[startHandler] scan started, id=%s", id)
	c.JSON(http.StatusAccepted, gin.H{"scan_id": id})
}

func statusHandler(c *gin.Context) {
	id := c.Param("id")
	log.Printf("[statusHandler] checking status for id=%s", id)

	st, ok := store.GetStatus(id)
	if !ok {
		log.Printf("[statusHandler] status not found for id=%s", id)
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, st)
}

func resultHandler(c *gin.Context) {
	id := c.Param("id")
	log.Printf("[resultHandler] fetching result for id=%s", id)

	status, ok := store.GetStatus(id)
	if !ok {
		log.Printf("[resultHandler] status not found for id=%s", id)
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	if !status.Done {
		log.Printf("[resultHandler] scan not ready for id=%s", id)
		c.JSON(http.StatusNotFound, gin.H{"error": "not found or not ready"})
		return
	}

	// if result built, reuse it:
	if res, ok := store.GetResult(id); ok && res.Result != nil {
		c.JSON(http.StatusOK, res)
		return
	}

	agg, err := aggregator.Build(id, aggregator.BuilderConfig{
		ZapCSVPath:    "/home/michal/GolandProjects/Scanropod/config/cwe-lists/zap-csv-fix.csv",
		WapitiCSVPath: "/home/michal/GolandProjects/Scanropod/config/cwe-lists/wapiti-csv.csv",
		NiktoCSVPath:  "/home/michal/GolandProjects/Scanropod/config/cwe-lists/nikto-csv-fix.csv",
		NucleiCSVPath: "/home/michal/GolandProjects/Scanropod/config/cwe-lists/nuclei-csv.csv",
	})
	if err != nil {
		log.Printf("[resultHandler] build aggregated report id=%s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build report"})
		return
	}

	res := status
	now := time.Now()
	res.FinishedAt = &now
	res.Done = true
	res.Result = &agg

	store.SetStatus(id, res)
	store.SetResult(id, res)

	c.JSON(http.StatusOK, res)
}

func stopHandler(c *gin.Context) {
	id := c.Param("id")
	log.Printf("[stopHandler] stopping scan id=%s", id)

	if err := scanner.StopScan(id); err != nil {
		log.Printf("[stopHandler] StopScan error for id=%s: %v", id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[stopHandler] stop signal sent for id=%s", id)
	c.JSON(http.StatusOK, gin.H{"status": "stopping"})
}
