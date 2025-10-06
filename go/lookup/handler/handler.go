package handler

import (
	"context"
	"net/http"
	"os"

	"ws-lookup/defs"
	"ws-lookup/model"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

func APIHandlerStart(ctx context.Context, conf *model.Config) {
	//---------------------------------------------------------------------------------------------------------------------
	// Initialize Echo webservice
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format:           "[${time_rfc3339}][${remote_ip} -> ${host}][${protocol}-${method}][${status}]: ${uri} | in: ${bytes_in} - out: ${bytes_out} | ${latency_human} | error: ${error}\n",
		CustomTimeFormat: clock.FormatRFC3339,
		Output:           os.Stdout,
	}))
	e.Use(middleware.Recover())
	e.Validator = &CustomValidator{validator: validator.New()}
	//---------------------------------------------------------------------------------------------------------------------
	// Handler
	lookupHandler := NewLookupHandler(ctx, *conf)
	domainHandler := NewDomainHandler(ctx, *conf)
	ipAddressHandler := NewIPAddressHandler(ctx, *conf)
	urlHandler := NewURLHandler(ctx, *conf)
	fileHandler := NewFileHandler(ctx, *conf)
	cveHandler := NewCVEHandler(ctx, *conf)
	//---------------------------------------------------------------------------------------------------------------------
	// Routes
	root := os.Getenv(defs.EnvApiRoot)
	if root == "" {
		root = defs.DefaultAPIRoot
	}
	rootApi := e.Group(root)
	/*
		API: Lookup
	*/
	lookup := rootApi.Group("/lookup")
	lookup.POST("", lookupHandler.Lookup)
	lookup.POST("/identify", lookupHandler.Identify)
	lookup.POST("/domain", domainHandler.Lookup)
	lookup.POST("/domains", domainHandler.LookupMultiple)
	lookup.POST("/ipaddress", ipAddressHandler.Lookup)
	lookup.POST("/ipaddresses", ipAddressHandler.LookupMultiple)
	lookup.POST("/url", urlHandler.Lookup)
	lookup.POST("/file", fileHandler.Lookup)
	lookup.POST("/cves", cveHandler.LookupMultiple)
	//---------------------------------------------------------------------------------------------------------------------
	// Start
	go func() {
		if err := e.Start(conf.App.Address); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatalf("server start failed: %v", err)
		}
	}()
	//---------------------------------------------------------------------------------------------------------------------
	// Wait for shutdown
	<-ctx.Done()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatalf("server shutdown failed: %v", err)
	}
}
