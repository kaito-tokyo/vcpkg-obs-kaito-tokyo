//go:build !windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	exePath, err := os.Executable()
	if err != nil {
		panic(fmt.Sprintf("failed to get executable path: %v", err))
	}

	outputDir := filepath.Dir(exePath)

	ciProxyServer, err := NewCIProxyServer(outputDir, os.Stdout, os.Stderr)
	if err != nil {
		panic(fmt.Sprintf("failed to create CIProxyServer: %v", err))
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:    net.JoinHostPort("127.0.0.1", port),
		Handler: ciProxyServer,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server closed: %v\n", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	sig := <-sigChan
	fmt.Fprintf(os.Stdout, "Received signal %s, shutting down...\n", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server shutdown failed: %v\n", err)
	}

	fmt.Fprintln(os.Stdout, "Server gracefully stopped.")
}
