package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CIProxyServer struct {
	AccessToken             string
	ArtifactDir             string
	BinarycacheReadwriteURL string
	BinarycacheURL          string
	CurlScriptsDir          string
	StderrWriter            io.Writer
	StdoutWriter            io.Writer
	TempDir                 string
}

func getAccessToken(tokenURL string, masterToken string) (string, error) {
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

func NewCIProxyServer(outputDir string, stdoutWriter io.Writer, stderrWriter io.Writer) (*CIProxyServer, error) {
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for output directory: %v", err)
	}

	if err := os.Chdir(absOutputDir); err != nil {
		return nil, fmt.Errorf("failed to change directory to output directory: %v", err)
	}

	artifactDir := filepath.Join(absOutputDir, "vcpkg_artifacts")
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create artifact directory: %v", err)
	}

	curlScriptsDir := filepath.Join(absOutputDir, "vcpkg_curlscripts")
	if err := os.MkdirAll(curlScriptsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create curl scripts directory: %v", err)
	}

	tempDir := filepath.Join(absOutputDir, "vcpkg_artifacts_tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	masterToken := os.Getenv("CIPROXY_MASTER_TOKEN")
	if masterToken == "" {
		return nil, fmt.Errorf("CIPROXY_MASTER_TOKEN environment variable is not set")
	}

	tokenURL := os.Getenv("CIPROXY_TOKEN_URL")
	if tokenURL == "" {
		return nil, fmt.Errorf("CIPROXY_TOKEN_URL environment variable is not set")
	}

	accessToken, err := getAccessToken(tokenURL, masterToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %v", err)
	}

	binarycacheURL := os.Getenv("CIPROXY_BINARYCACHE_URL")
	if binarycacheURL == "" {
		return nil, fmt.Errorf("CIPROXY_BINARYCACHE_URL environment variable is not set")
	}

	binarycacheReadwriteURL := os.Getenv("CIPROXY_BINARYCACHE_READWRITE_URL")
	if binarycacheReadwriteURL == "" {
		return nil, fmt.Errorf("CIPROXY_BINARYCACHE_READWRITE_URL environment variable is not set")
	}

	return &CIProxyServer{
		AccessToken:             accessToken,
		ArtifactDir:             artifactDir,
		BinarycacheURL:          binarycacheURL,
		BinarycacheReadwriteURL: binarycacheReadwriteURL,
		CurlScriptsDir:          curlScriptsDir,
		StderrWriter:            stderrWriter,
		StdoutWriter:            stdoutWriter,
		TempDir:                 tempDir,
	}, nil
}

type PostBinarycacheResponse struct {
	PresignedUrl string `json:"presignedUrl"`
}

func (s *CIProxyServer) getPresignedURL(accessToken string, key string) (string, error) {
	req, err := http.NewRequest("POST", s.BinarycacheReadwriteURL+key, nil)
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

func (s *CIProxyServer) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path

	presignedURL, err := s.getPresignedURL(s.AccessToken, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		fmt.Fprintln(s.StderrWriter, "Unauthorized")
		return
	}

	filename := filepath.Base(key)

	// Validate that filename is safe
	if !isSafeFilename(filename) {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		fmt.Fprintln(s.StderrWriter, "Invalid file name")
		return
	}

	finalPath := filepath.Join(s.ArtifactDir, filename)
	tempPath := filepath.Join(s.TempDir, filename)

	tempFile, err := os.Create(tempPath)
	if err != nil {
		os.Remove(tempPath)
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		fmt.Fprintln(s.StderrWriter, "Failed to create temp file")
		return
	}

	_, err = io.Copy(tempFile, r.Body)
	tempFile.Close()
	if err != nil {
		os.Remove(tempPath)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		fmt.Fprintln(s.StderrWriter, "Failed to write file")
		return
	}

	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		http.Error(w, "Failed to commit artifact", http.StatusInternalServerError)
		fmt.Fprintln(s.StderrWriter, "Failed to commit artifact")
		return
	}

	safeFinalPath := filepath.ToSlash(finalPath)
	entry := fmt.Sprintf(
		"url = \"%s\"\n"+
			"upload-file = \"%s\"\n"+
			"header = \"Content-Type: application/zip\"\n"+
			"header = \"Cache-Control: public, max-age=86400\"\n",
		presignedURL, safeFinalPath,
	)

	configPath := filepath.Join(s.CurlScriptsDir, filename+".txt")
	if err := os.WriteFile(configPath, []byte(entry), 0644); err != nil {
		http.Error(w, "Failed to write upload config", http.StatusInternalServerError)
		fmt.Fprintln(s.StderrWriter, "Failed to write upload config")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *CIProxyServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.BinarycacheURL+r.URL.Path, http.StatusTemporaryRedirect)
}

func (s *CIProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
