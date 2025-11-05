package context

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/free5gc/smf/internal/logger"
)

// WNC: UPF HTTP client for Router Advertisement injection (Phase 3.2.4)
// This file contains HTTP client code to avoid import cycles with consumer package

// upfInjectRARequest represents the HTTP request for RA injection
type upfInjectRARequest struct {
	SEID     uint64 `json:"seid"`
	PDRID    uint16 `json:"pdrId"`
	RAPacket string `json:"raPacket"` // Base64-encoded
}

// upfInjectRAResponse represents the HTTP response from UPF
type upfInjectRAResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// sendRouterAdvertisementViaHTTPClient sends an RA packet to UPF via HTTP
func sendRouterAdvertisementViaHTTPClient(upfHTTPEndpoint string, seid uint64, pdrID uint16, raPacket []byte) error {
	if upfHTTPEndpoint == "" {
		return fmt.Errorf("WNC: UPF HTTP endpoint is empty")
	}

	if len(raPacket) == 0 {
		return fmt.Errorf("WNC: RA packet is empty")
	}

	logger.PfcpLog.Infof("WNC: Sending RA to UPF via HTTP (endpoint=%s, SEID=%d, PDR_ID=%d, packet_len=%d)",
		upfHTTPEndpoint, seid, pdrID, len(raPacket))

	// Base64 encode the RA packet
	encodedPacket := base64.StdEncoding.EncodeToString(raPacket)

	// Prepare request
	req := upfInjectRARequest{
		SEID:     seid,
		PDRID:    pdrID,
		RAPacket: encodedPacket,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("WNC: Failed to marshal RA request: %w", err)
	}

	// Build full URL
	url := fmt.Sprintf("%s/upf/v1/inject-ra", upfHTTPEndpoint)

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("WNC: Failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	logger.PfcpLog.Debugf("WNC: Sending HTTP POST to %s", url)

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("WNC: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("WNC: Failed to read response body: %w", err)
	}

	// Parse response
	var raResp upfInjectRAResponse
	if err := json.Unmarshal(body, &raResp); err != nil {
		return fmt.Errorf("WNC: Failed to parse response (status=%d): %w", resp.StatusCode, err)
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		logger.PfcpLog.Errorf("WNC: UPF returned error (status=%d): %s",
			resp.StatusCode, raResp.Message)
		return fmt.Errorf("WNC: UPF RA injection failed (status=%d): %s",
			resp.StatusCode, raResp.Message)
	}

	// Check success flag
	if !raResp.Success {
		logger.PfcpLog.Errorf("WNC: UPF RA injection failed: %s", raResp.Message)
		return fmt.Errorf("WNC: UPF RA injection failed: %s", raResp.Message)
	}

	logger.PfcpLog.Infof("WNC: RA successfully injected via UPF (SEID=%d, PDR_ID=%d): %s",
		seid, pdrID, raResp.Message)

	return nil
}
