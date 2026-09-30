// Command helm-gateway runs the shared Kernel gateway runtime.
package main

import (
	"context"
	"fmt"
	gatewayruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/runtime"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := gatewayruntime.Run(ctx, os.Args[1:], os.Getenv, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "helm-gateway:", err)
		os.Exit(1)
	}
}
