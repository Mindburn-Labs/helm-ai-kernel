// Package gdocs_drive provides a HELM connector for Google Docs and Google Drive.
//
// Architecture:
//   - types.go:     Request/response types for Docs and Drive operations
//   - client.go:    HTTP client stub (requires OAuth2 credentials for production use)
//   - connector.go: High-level connector composing client + ZeroTrust gate + ProofGraph
//
// Per HELM Standard v1.2: every tool call becomes an INTENT -> EFFECT chain
// in the ProofGraph DAG.
package gdocs_drive

import "time"

// ConnectorID is the canonical identifier for this connector.
const ConnectorID = "gdocs-drive-v1"

// AllowedDataClasses returns the data class allowlist for the Google Docs/Drive connector.
func AllowedDataClasses() []string {
	return []string{
		"gdocs.document.read",
		"gdocs.document.create",
		"gdocs.document.append",
		"gdrive.file.list",
		"gdrive.file.get",
	}
}

// toolDataClassMap maps tool names to their required data classes.
var toolDataClassMap = map[string]string{
	"gdocs.read_document":      "gdocs.document.read",
	"gdocs.create_document":    "gdocs.document.create",
	"gdocs.append_to_document": "gdocs.document.append",
	"gdrive.list_files":        "gdrive.file.list",
	"gdrive.get_file":          "gdrive.file.get",
}

// DocumentContent represents the content of a Google Docs document.
type DocumentContent struct {
	DocumentID   string    `json:"document_id"`
	Title        string    `json:"title"`
	Body         string    `json:"body"`
	LastModified time.Time `json:"last_modified"`
}

// CreateDocRequest is the request to create a new Google Docs document.
type CreateDocRequest struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	FolderID string `json:"folder_id,omitempty"`
}

// CreateDocResponse is the response after creating a document.
type CreateDocResponse struct {
	DocumentID string `json:"document_id"`
	HtmlLink   string `json:"html_link"`
}

// AppendRequest is the request to append content to a document.
type AppendRequest struct {
	DocumentID string `json:"document_id"`
	Content    string `json:"content"`
}

// FileInfo represents metadata about a file in Google Drive.
type FileInfo struct {
	FileID     string    `json:"file_id"`
	Name       string    `json:"name"`
	MimeType   string    `json:"mime_type"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

// ListFilesResponse is the response from listing files in Google Drive.
type ListFilesResponse struct {
	Files         []FileInfo `json:"files"`
	NextPageToken string     `json:"next_page_token,omitempty"`
}
