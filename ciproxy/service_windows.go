//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/sys/windows/svc"
)

type WindowsService struct {
	Server *http.Server
}

func (s *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	go func() {
		if err := s.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server closed: %v\n", err)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			fmt.Printf("Received Cmd %s, shutting down...\n", c.Cmd)
			changes <- svc.Status{State: svc.StopPending}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.Server.Shutdown(ctx); err != nil {
				fmt.Printf("Server shutdown failed: %v\n", err)
			}
			fmt.Println("Server gracefully stopped.")
			return
		}
	}
}

func RunAsService(server *http.Server) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if we are running in service: %v", err)
	}

	if isService {
		svc.Run("ciproxy", &WindowsService{Server: server})
	} else {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server closed: %v\n", err)
		}
	}
}
