//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

type WindowsService struct {
}

func (s *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	stderrPath := os.Getenv("STDERR_PATH")
	if stderrPath == "" {
		fmt.Fprintf(os.Stderr, "failed to get STDERR_PATH\n")
		return true, 2001
	}
	stderrWriter, err := os.OpenFile(stderrPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open stderr log file: %v\n", err)
		return true, 2002
	}
	defer stderrWriter.Close()
	os.Stderr = stderrWriter

	stdoutPath := os.Getenv("STDOUT_PATH")
	if stdoutPath == "" {
		fmt.Fprintln(os.Stderr, "failed to get STDOUT_PATH")
		return true, 2003
	}
	stdoutWriter, err := os.OpenFile(stdoutPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open stdout log file: %v\n", err)
		return true, 2004
	}
	defer stdoutWriter.Close()
	os.Stdout = stdoutWriter

	workingDir := os.Getenv("WORKING_DIRECTORY")
	if workingDir == "" {
		fmt.Fprintln(os.Stderr, "failed to get WORKING_DIRECTORY")
		return true, 2005
	}
	if err := os.Chdir(workingDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to change working directory: %v\n", err)
		return true, 2006
	}

	pidPath := filepath.Join(workingDir, "ciproxy.pid")
	pidData := []byte(fmt.Sprintf("%d", os.Getpid()))
	if err := os.WriteFile(pidPath, pidData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write PID file: %v\n", err)
		return true, 2007
	}
	defer os.Remove(pidPath)

	ciProxyServer, err := NewCIProxyServer(workingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create CIProxyServer: %v\n", err)
		return true, 2008
	}

	port := os.Getenv("PORT")
	if port == "" {
		fmt.Fprintln(os.Stderr, "failed to get PORT")
		return true, 2009
	}

	server := &http.Server{
		Addr:    net.JoinHostPort("127.0.0.1", port),
		Handler: ciProxyServer,
	}

	listen, err := net.Listen("tcp", server.Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v\n", server.Addr, err)
		return true, 2010
	}

	go func() {
		if err := server.Serve(listen); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "CIProxy closed: %v\n", err)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			fmt.Fprintf(os.Stderr, "received Cmd %v, shutting down...\n", c.Cmd)
			changes <- svc.Status{State: svc.StopPending}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "CIProxy shutdown failed: %v\n", err)
			}

			fmt.Fprintln(os.Stderr, "CIProxy gracefully stopped.")

			return false, 0
		}
	}
}

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		panic(fmt.Sprintf("failed to determine if we are running in service: %v", err))
	}

	if isService {
		svc.Run("ciproxy", &WindowsService{})
	} else {
		panic("not running as a Windows service")
	}
}
