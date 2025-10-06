package main

import (
	"context"
	"dissem-worker-alert-easm/config"
	"dissem-worker-alert-easm/internal/processor"
	"fmt"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	panicIfError(err)
	defer logger.Sync()
	conf, err := config.New()
	panicIfError(err)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer stop()

	p := processor.NewProcessor(conf, logger)
	w := p.CreateProcessor("easm")
	go w.Start()

	<-ctx.Done()
	fmt.Println("Received stop signal: ", ctx.Err())

}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
