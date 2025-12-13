package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
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
	accessToken string
}

func (s CIProxyServer) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path

	presignedURL, err := getPresignedURL(s.accessToken, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		fmt.Printf("Failed to get presigned URL: %v\n", err)
		return
	}

	req, err := http.NewRequest(http.MethodPut, presignedURL, r.Body)
	if err != nil {
		http.Error(w, "Error creating R2 request", http.StatusInternalServerError)
		fmt.Printf("Failed to create R2 request: %v\n", err)
		return
	}

	req.ContentLength = r.ContentLength

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "R2 transfer failed", http.StatusBadGateway)
		fmt.Printf("R2 transfer failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func (s CIProxyServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	binarycacheURL := "https://readwrite.vcpkg-obs.kaito.tokyo/binarycache"
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

	server := CIProxyServer{accessToken: accessToken}

	http.HandleFunc("/", server.handle)

	fmt.Printf("Starting CI Proxy Server on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		panic(err)
	}
}
