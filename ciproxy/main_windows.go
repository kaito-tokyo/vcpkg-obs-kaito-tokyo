//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

type WindowsService struct {
	OutputDir    string
	StdoutWriter io.Writer
	StderrWriter io.Writer
}

func (s *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ciProxyServer, err := NewCIProxyServer(s.OutputDir, s.StdoutWriter, s.StderrWriter)
	if err != nil {
		fmt.Fprintf(s.StderrWriter, "failed to create CIProxyServer: %v\n", err)
		return true, 1000
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
			fmt.Fprintf(s.StderrWriter, "Server closed: %v\n", err)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			fmt.Fprintf(s.StderrWriter, "Received Cmd %v, shutting down...\n", c.Cmd)
			changes <- svc.Status{State: svc.StopPending}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				fmt.Fprintf(s.StderrWriter, "Server shutdown failed: %v\n", err)
			}

			fmt.Fprintln(s.StderrWriter, "Server gracefully stopped.")

			return false, 0
		}
	}
}

func main() {
	exePath, err := os.Executable()
	if err != nil {
		panic(fmt.Sprintf("failed to get executable path: %v", err))
	}

	outputDir := filepath.Dir(exePath)

	stdoutPath := filepath.Join(outputDir, "stdout.log")
	stdoutWriter, err := os.OpenFile(stdoutPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("failed to open stdout log file: %v", err))
	}

	stderrPath := filepath.Join(outputDir, "stderr.log")
	stderrWriter, err := os.OpenFile(stderrPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("failed to open stderr log file: %v", err))
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(stderrWriter, "failed to determine if we are running in service: %v\n", err)
		os.Exit(1)
	}

	if isService {
		service := &WindowsService{
			OutputDir:    outputDir,
			StdoutWriter: stdoutWriter,
			StderrWriter: stderrWriter,
		}
		svc.Run("ciproxy", service)
	} else {
		fmt.Fprintln(stderrWriter, "not running as a Windows service")
		os.Exit(2)
	}
}
