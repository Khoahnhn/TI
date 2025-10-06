package main

import (
	"context"
	_ "embed"
	"flag"
	"os/signal"
	"strings"
	"syscall"

	vcslogging "gitlab.viettelcyber.com/ti-library/vcslogging-golang"

	"proc-worker-alert-cve/defs"
	"proc-worker-alert-cve/model"
	"proc-worker-alert-cve/processor"
)

//go:embed template/images/BG_Top_Vi.png
var imgTop string

//go:embed template/images/BG_Bottom.png
var imgBottom string

//go:embed template/images/BG_Top_En.png
var imgTopEn string

//go:embed template/images/BG_Bottom_en.png
var imgBottomEn string

//go:embed template/images/BG_Signature.png
var imgSign string

//go:embed template/images/imail.png
var imgMail string

//go:embed template/images/iweb.png
var imgWeb string

//go:embed template/images/iphone.png
var imgPhone string

//go:embed template/images/imap.png
var imgMap string

func main() {
	var (
		name       string
		configFile string
	)
	flag.StringVar(&name, "n", "", "Processor name")
	flag.StringVar(&name, "name", "", "Processor name")
	flag.StringVar(&configFile, "c", "", "Config file")
	flag.StringVar(&configFile, "config", defs.DefaultConfigFilePath, "Config file")
	flag.Parse()

	conf, err := model.LoadConfig(configFile)
	if err != nil {
		panic(err)
	}
	// Initial logging vcs
	vcslogging.New(&vcslogging.LoggingProps{
		LogLevel:        vcslogging.LoggingLevel(conf.Core.LogLevel),
		ApplicationCode: "dissemination",
		ServiceCode:     "proc-worker-alert-cve",
	})

	conf.TemplateEmail.BGTop = imgTop
	conf.TemplateEmail.BGBottom = imgBottom
	conf.TemplateEmail.BGSignature = imgSign
	conf.TemplateEmail.ImgMail = imgMail
	conf.TemplateEmail.ImgMap = imgMap
	conf.TemplateEmail.ImgPhone = imgPhone
	conf.TemplateEmail.ImgWeb = imgWeb
	conf.TemplateEmail.BGTopEn = imgTopEn
	conf.TemplateEmail.BGBottomEn = imgBottomEn

	globalContext, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	if strings.Contains(name, ",") {
		processors := strings.Split(name, ",")
		for _, p := range processors {
			ps := processor.NewProcessor(globalContext, p, *conf)
			ps.Start()
		}
	} else {
		ps := processor.NewProcessor(globalContext, name, *conf)
		ps.Start()
	}
	select {}

}
