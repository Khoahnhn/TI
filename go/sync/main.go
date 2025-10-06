package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"gitlab.viettelcyber.com/threat-intelligence/ti-crawler/general-crawler/cve-sync-lifecycle/model"
	"gitlab.viettelcyber.com/threat-intelligence/ti-crawler/general-crawler/cve-sync-lifecycle/processor"
	"gopkg.in/yaml.v3"
)

func main() {
	var modules string
	var cve string
	var configFile string
	flag.StringVar(&modules, "m", "vti,nvd", "Processor: nvd,vti,cve,report")
	flag.StringVar(&cve, "cve", "", "List cve, eg: CVE-2024-23456")
	flag.StringVar(&configFile, "config", "", "path of config file")
	flag.Parse()

	if modules == "" {
		panic("modules missing")
	}
	if configPath := os.Getenv("CONFIG_FILE_PATH"); configPath != "" {
		configFile = configPath
	}
	if configFile == "" {
		configFile = "config.yaml"
	}
	log.Println("config file ", configFile)
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var conf model.Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&conf); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer stop()
	var listCve []string
	if cve != "" {
		listCve = strings.Split(cve, ",")
	}

	processFactory := processor.NewProcessorFactory(&conf, ctx, listCve)
	processors := strings.Split(modules, ",")
	wg := new(sync.WaitGroup)
	for _, elem := range processors {
		wg.Add(1)
		go func(elem string) {
			defer wg.Done()
			worker := processFactory.CreateProcessor(processor.ProcessType(elem))
			worker.Start()
		}(elem)
	}

	wg.Wait()
	fmt.Println("Sync finished")
}
