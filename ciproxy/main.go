package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	ArtifactDir    = "vcpkg_artifacts"
	CurlScriptsDir = "vcpkg_curlscripts"
	TempDir        = "vcpkg_artifacts_tmp"
)

func getAccessToken(masterToken string) (string, error) {
	tokenURL := "https://readwrite.vcpkg-obs.kaito.tokyo/token"

	data := url.Values{}
	data.Set("master_token", masterToken)
	encodedData := data.Encode()
	bodyReader := strings.NewReader(encodedData)

	req, err := http.NewRequest("POST", tokenURL, bodyReader)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get access token: %v", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read access token: %v", err)
	}

	accessToken := strings.TrimSpace(string(respBody))

	return accessToken, nil
}

func main() {
	if err := os.MkdirAll(ArtifactDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ArtifactDir: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(TempDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create TempDir: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(CurlScriptsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create CurlScriptsDir: %v\n", err)
		os.Exit(1)
	}

	envMasterToken := os.Getenv("MASTER_TOKEN")
	if envMasterToken == "" {
		panic("MASTER_TOKEN environment variable is not set")
	}
	masterToken := strings.TrimSpace(envMasterToken)

	port := os.Getenv("PORT")
	if port == "" {
		panic("PORT environment variable is not set")
	}

	accessToken, err := getAccessToken(masterToken)
	if err != nil {
		panic(err)
	}

	server := &http.Server{
		Addr:    net.JoinHostPort("127.0.0.1", port),
		Handler: http.HandlerFunc((&CIProxyServer{AccessToken: accessToken}).handle),
	}

	RunAsService(server)
}
