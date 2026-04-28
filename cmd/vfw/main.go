package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"vfw/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cli, err := app.New(os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vfw: %v\n", err)
		os.Exit(1)
	}

	if err := cli.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vfw: %v\n", err)
		os.Exit(1)
	}
}
