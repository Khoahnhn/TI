package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gopkg.in/yaml.v2"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/handler"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

func main() {
	configFile := os.Getenv(defs.EnvConfigFilePath)
	if configFile == "" {
		flag.StringVar(&configFile, "c", "", "config file name")
		flag.StringVar(&configFile, "config", "", "config file name")
		flag.Parse()
	}
	if configFile == "" {
		configFile = defs.DefaultConfigFilePath
	}
	f, err := os.Open(configFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var conf *model.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&conf)
	if err != nil {
		panic(err)
	}
	// Start
	go handler.APIHandlerStart(conf)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	select {
	// Wait
	case <-ch:
		fmt.Println("unregistering handler...")
		clock.Sleep(clock.Second)
		fmt.Println("exit!")
	}
}
