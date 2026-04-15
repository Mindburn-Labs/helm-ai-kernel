// Package gdocs_drive is a STUB connector. All public methods return "not connected"
// errors until a real Google Docs/Drive API client ships. Tracked as roadmap
// item P2-04 (marked-experimental connector set). DO NOT depend on this package
// for production workloads.
package gdocs_drive

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is an HTTP client for the Google Docs and Google Drive APIs. STUB —
// see package doc.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Google Docs/Drive client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ReadDocument retrieves the content of a Google Docs document.
func (c *Client) ReadDocument(_ context.Context, documentID string) (*DocumentContent, error) {
	return nil, fmt.Errorf("gdocs_drive: ReadDocument(%q): not connected: requires OAuth2 credentials", documentID)
}

// CreateDocument creates a new Google Docs document.
func (c *Client) CreateDocument(_ context.Context, req *CreateDocRequest) (*CreateDocResponse, error) {
	return nil, fmt.Errorf("gdocs_drive: CreateDocument(%q): not connected: requires OAuth2 credentials", req.Title)
}

// AppendToDocument appends content to an existing Google Docs document.
func (c *Client) AppendToDocument(_ context.Context, req *AppendRequest) error {
	return fmt.Errorf("gdocs_drive: AppendToDocument(%q): not connected: requires OAuth2 credentials", req.DocumentID)
}

// ListFiles lists files in Google Drive.
func (c *Client) ListFiles(_ context.Context, pageToken string) (*ListFilesResponse, error) {
	return nil, fmt.Errorf("gdocs_drive: ListFiles(pageToken=%q): not connected: requires OAuth2 credentials", pageToken)
}

// GetFile retrieves metadata for a specific file in Google Drive.
func (c *Client) GetFile(_ context.Context, fileID string) (*FileInfo, error) {
	return nil, fmt.Errorf("gdocs_drive: GetFile(%q): not connected: requires OAuth2 credentials", fileID)
}
