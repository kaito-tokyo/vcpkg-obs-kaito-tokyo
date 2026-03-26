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
	workingDir, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintf("failed to get current working directory: %v", err))
	}

	pidPath := filepath.Join(workingDir, "ciproxy.pid")
	pidData := []byte(fmt.Sprintf("%d", os.Getpid()))
	if err := os.WriteFile(pidPath, pidData, 0644); err != nil {
		panic(fmt.Sprintf("failed to write PID file: %v", err))
	}
	defer os.Remove(pidPath)

	ciProxyServer, err := NewCIProxyServer(workingDir)
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
			fmt.Fprintf(os.Stderr, "CIProxy closed: %v\n", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	sig := <-sigChan
	fmt.Fprintf(os.Stderr, "received signal %s, shutting down...\n", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "CIProxy shutdown failed: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "CIProxy gracefully stopped.")
}
