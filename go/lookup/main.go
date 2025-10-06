package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"ws-lookup/defs"
	"ws-lookup/handler"
	"ws-lookup/model"
)

func main() {
	//---------------------------------------------------------------------------------------------------------------------
	// Parse command line opts
	var configFile string
	flag.StringVar(&configFile, "c", "", "config file name")
	flag.StringVar(&configFile, "config", "", "config file name")
	flag.Parse()
	//---------------------------------------------------------------------------------------------------------------------
	// Initialize config path
	if configFile == "" {
		configFile = os.Getenv(defs.EnvConfigFilePath)
		if configFile == "" {
			configFile = defs.DefaultConfigFilePath
		}
	}
	//---------------------------------------------------------------------------------------------------------------------
	// Parse config
	f, err := os.ReadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to read config file: %w", err))
	}
	var conf *model.Config
	if err = yaml.Unmarshal(f, &conf); err != nil {
		panic(fmt.Errorf("failed to parse config file: %w", err))
	}
	//---------------------------------------------------------------------------------------------------------------------
	// Start webservice
	globalContext, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer cancel()
	handler.APIHandlerStart(globalContext, conf)
	//---------------------------------------------------------------------------------------------------------------------
	// Shutdown
	log.Println("ws-lookup has shut down")
}
