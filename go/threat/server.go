package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/handler"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"

	"gopkg.in/yaml.v3"
)

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "", "config file name")
	flag.StringVar(&configFile, "config", "", "config file name")
	flag.Parse()
	if configFile == "" {
		configFile = os.Getenv(defs.EnvConfigFilePath)
		if configFile == "" {
			configFile = defs.DefaultConfigFilePath
		}
	}
	f, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var conf *model.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&conf)
	if err != nil {
		log.Fatal(err)
	}

	globalContext, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer cancel()
	handler.APIHandlerStart(globalContext, conf)

	log.Println("ws-threat has shut down")
}
