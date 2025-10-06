package handler

import (
	"context"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

var logger pencil.Logger

func init() {
	logger, _ = pencil.New(defs.HandlerMain, pencil.DebugLevel, true, os.Stdout)
}

func APIHandlerStart(ctx context.Context, conf *model.Config) {
	// ======================================================================================
	// Initialization Echo webservice
	e := echo.New()
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format:           "[${time_rfc3339}][${remote_ip} -> ${host}][${protocol}-${method}][${status}]: ${uri} | in: ${bytes_in} - out: ${bytes_out} | ${latency_human} | error: ${error}\n",
		CustomTimeFormat: clock.FormatRFC3339,
		Output:           os.Stdout,
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.RemoveTrailingSlash())
	e.Validator = &CustomValidator{validator: validator.New()}
	// ======================================================================================
	// Handler
	alertHandler := NewAlertHandler(*conf)
	ttiHandler := NewTTIHandler(*conf)
	cveHandler := NewCVEHandler(*conf, false)
	cpeHandler := NewCPEHandler(*conf)
	indicatorHandler := NewIndicatorHandler(ctx, *conf)
	// ======================================================================================
	customeMiddleware := NewMiddleware(conf)
	// Route
	root := os.Getenv(defs.EnvApiRoot)
	if root == "" {
		root = defs.DefaultApiRoot
	}
	rootApi := e.Group(root)
	/*
		Alert Group
	*/
	alert := rootApi.Group("/alert")
	alert.POST("/export", alertHandler.Export)
	/*
		TTI Group
	*/
	tti := rootApi.Group("/tti")
	ttiAlert := tti.Group("/alert")
	ttiAlert.POST("/export", ttiHandler.Export)
	ttiAlert.POST("/delivery", ttiHandler.Delivery)
	/*
		Vulnerability Group
	*/
	vulnerability := rootApi.Group("/vulnerability")
	/*
		CVE Sub-Group
	*/
	cve := vulnerability.Group("/cve")
	cve.GET("/identify", cveHandler.Identify, ExtractToken)
	cve.GET("/config", cveHandler.Config)
	cve.POST("/search", cveHandler.Search)
	cve.POST("/validate-cve", cveHandler.ValidateCVE, customeMiddleware.verifyApiKey)
	cve.POST("/lifecycle-cve", cveHandler.LifecycleCVE, customeMiddleware.verifyApiKey)
	cve.GET("/:id/export-cve", cveHandler.ExportCveById, ExtractToken)
	cve.POST("/statistic", cveHandler.Statistic)
	cve.POST("/export-excel", cveHandler.ExportListCve)
	cve.GET("/:id", cveHandler.Detail)
	cve.PUT("/:id", cveHandler.Edit, ExtractToken)
	cve.GET("/:id/exist", cveHandler.Exist)
	cve.GET("/:id/history", cveHandler.CVEHistory)
	cve.GET("/:id/history-epss", cveHandler.EPSSHistory)
	cve.POST("/:id", cveHandler.Create, ExtractToken)
	cve.POST("/:id/confirm", cveHandler.Confirm, ExtractToken)
	cve.POST("/reject", cveHandler.RejectCVEs, ExtractToken)
	cve.POST("/check_reject", cveHandler.CheckReject, ExtractToken)
	cve.POST("/:id/lifecycle", cveHandler.CreateLifecycle, customeMiddleware.verifyApiKey)
	cve.GET("/:id/lifecycle", cveHandler.CVELifeCycleV2)
	cve.POST("/internal-flag", cveHandler.CVEsInternalFlag, ExtractToken)
	cve.POST("/internal-flag/search", cveHandler.SearchInternalFlag)

	/*
		CPE Sub-Group
	*/
	cpe := vulnerability.Group("/cpe")
	cpe.GET("/config", cpeHandler.Config)
	cpe.GET("/statistic", cpeHandler.Statistic)
	cpe.POST("/search", cpeHandler.Search)
	cpe.GET("/exist", cpeHandler.Exist)
	cpe.POST("", cpeHandler.Create, ExtractToken)
	cpe.POST("/delete", cpeHandler.Delete)
	cpe.GET("/popular/statistic", cpeHandler.StatisticPopular)
	cpe.POST("/popular/search", cpeHandler.SearchPopular)
	cpe.POST("/popular", cpeHandler.CreatePopular, ExtractToken)
	cpe.POST("/popular/delete", cpeHandler.DeletePopular, ExtractToken)
	cpe.GET("/suggest/vendor", cpeHandler.SuggestVendor)
	cpe.GET("/suggest/product", cpeHandler.SuggestProduct)
	cpe.GET("/suggest/version", cpeHandler.SuggestVersion)
	cpe.GET("/suggest/update", cpeHandler.SuggestUpdate)
	cpe.GET("/search/vendor", cpeHandler.SearchVendor)
	cpe.GET("/search/product", cpeHandler.SearchProduct)
	cpe.GET("/search/version", cpeHandler.SearchVersion)
	cpe.GET("/search/update", cpeHandler.SearchUpdate)
	/*
		Indicator
	*/
	indicator := rootApi.Group("/indicator")
	indicator.GET("/config", indicatorHandler.Config)
	indicator.POST("/search", indicatorHandler.Search)
	indicator.GET("/statistic", indicatorHandler.Statistic)
	indicator.POST("", indicatorHandler.Create)
	indicator.PUT("/:id", indicatorHandler.Edit)
	indicator.GET("/:id/history", indicatorHandler.History)
	indicator.POST("/validate", indicatorHandler.Validate)
	indicator.POST("/predict", indicatorHandler.Predict)
	indicator.GET("/tags", indicatorHandler.Tags)
	// ======================================================================================
	// Start
	go func() {
		if err := e.Start(conf.App.Address); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatalf("server start failed: %v", err)
		}
	}()
	// ======================================================================================
	// Shutdown
	<-ctx.Done()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatalf("server shutdown failed: %v", err)
	}
}
