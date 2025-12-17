package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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

type PostBinarycacheResponse struct {
	PresignedUrl string `json:"presignedUrl"`
}

func getPresignedURL(accessToken string, key string) (string, error) {
	binarycacheURL := "https://readwrite.vcpkg-obs.kaito.tokyo/binarycache"
	fmt.Printf("Getting presigned URL for key: %s\n", key)

	req, err := http.NewRequest("POST", binarycacheURL+key, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get presigned URL: %v", resp.StatusCode)
	}

	var postBinarycacheResponse PostBinarycacheResponse
	err = json.NewDecoder(resp.Body).Decode(&postBinarycacheResponse)
	if err != nil {
		return "", fmt.Errorf("failed to decode response body: %v", err)
	}

	presignedURL := postBinarycacheResponse.PresignedUrl
	if presignedURL == "" {
		return "", fmt.Errorf("missing presignedUrl in response body")
	}

	return presignedURL, nil
}

type CIProxyServer struct {
	AccessToken string
}

// isSafeFilename returns true if the filename contains only safe characters and does not allow any path separators or "..".
func isSafeFilename(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	// Reject any path separators or directory traversal
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return false
	}
	return true
}

func (s CIProxyServer) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path

	presignedURL, err := getPresignedURL(s.AccessToken, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	filename := filepath.Base(key)

	// Validate that filename is safe
	if !isSafeFilename(filename) {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		return
	}

	finalPath := filepath.Join(ArtifactDir, filename)
	tempPath := filepath.Join(TempDir, filename)

	tempFile, err := os.Create(tempPath)
	if err != nil {
		os.Remove(tempPath)
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}

	_, err = io.Copy(tempFile, r.Body)
	tempFile.Close()
	if err != nil {
		os.Remove(tempPath)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		http.Error(w, "Failed to commit artifact", http.StatusInternalServerError)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	entry := fmt.Sprintf(
		"url = \"%s\"\n"+
			"upload-file = \"%s\"\n"+
			"header = \"Content-Type: %s\"\n"+
			"header = \"Cache-Control: public, max-age=31536000, immutable\"\n"+
			"next\n",
		presignedURL, finalPath, contentType,
	)

	configPath := filepath.Join(CurlScriptsDir, filename+".txt")
	if err := os.WriteFile(configPath, []byte(entry), 0644); err != nil {
		fmt.Printf("Failed to write config file: %v\n", err)
		http.Error(w, "Failed to write upload config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s CIProxyServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	binarycacheURL := "https://vcpkg-obs.kaito.tokyo"
	http.Redirect(w, r, binarycacheURL+r.URL.Path, http.StatusTemporaryRedirect)
}

func (s CIProxyServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		s.handleRedirect(w, r)
	case http.MethodPut:
		s.handleFileUpload(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	// Ensure ArtifactDir and TempDir exist
	if err := os.MkdirAll(ArtifactDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ArtifactDir: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(TempDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create TempDir: %v\n", err)
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
		Addr:    ":" + port,
		Handler: nil,
	}
	proxyServer := CIProxyServer{AccessToken: accessToken}
	http.HandleFunc("/", proxyServer.handle)

	go func() {
		fmt.Printf("Starting CI Proxy Server on port %s...\n", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server ListenAndServe: %v\n", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	fmt.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("Server forced to shutdown: %v\n", err)
	}

	fmt.Println("Server exiting")
}
