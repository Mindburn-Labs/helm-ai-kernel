//go:build conformance

// Package identity provides SCIM 2.0 provisioning server for enterprise IdP integration.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ── SCIM 2.0 Types ────────────────────────────────────────────

// SCIMUser represents a SCIM 2.0 User Resource (RFC 7643).
type SCIMUser struct {
	Schemas    []string       `json:"schemas"`
	ID         string         `json:"id"`
	ExternalID string         `json:"externalId,omitempty"`
	UserName   string         `json:"userName"`
	Name       SCIMName       `json:"name"`
	Emails     []SCIMEmail    `json:"emails,omitempty"`
	Active     bool           `json:"active"`
	Groups     []SCIMGroupRef `json:"groups,omitempty"`
	Meta       SCIMMeta       `json:"meta"`
	TenantID   string         `json:"urn:helm:params:scim:tenantId,omitempty"`
}

// SCIMName represents the name component of a SCIM user.
type SCIMName struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	Formatted  string `json:"formatted,omitempty"`
}

// SCIMEmail represents a SCIM email address.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary"`
}

// SCIMGroupRef is a reference to a group from a user resource.
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// SCIMMeta contains resource metadata per SCIM spec.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
}

// SCIMGroup represents a SCIM 2.0 Group Resource.
type SCIMGroup struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id"`
	DisplayName string         `json:"displayName"`
	Members     []SCIMGroupRef `json:"members,omitempty"`
	Meta        SCIMMeta       `json:"meta"`
	TenantID    string         `json:"urn:helm:params:scim:tenantId,omitempty"`
}

// SCIMListResponse is the SCIM list response envelope.
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMError represents a SCIM error response.
type SCIMError struct {
	Schemas []string `json:"schemas"`
	Detail  string   `json:"detail"`
	Status  string   `json:"status"`
}

// ── SCIM Server ───────────────────────────────────────────────

const (
	scimCoreSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// SCIMServer provides SCIM 2.0 provisioning endpoints.
type SCIMServer struct {
	mu     sync.RWMutex
	users  map[string]*SCIMUser
	groups map[string]*SCIMGroup
}

// NewSCIMServer creates a new SCIM server instance.
func NewSCIMServer() *SCIMServer {
	return &SCIMServer{
		users:  make(map[string]*SCIMUser),
		groups: make(map[string]*SCIMGroup),
	}
}

func (s *SCIMServer) generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// UUID v4 format: 8-4-4-4-12
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// RegisterRoutes registers SCIM endpoints on the given mux.
func (s *SCIMServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/scim/v2/Users", s.handleUsers)
	mux.HandleFunc("/scim/v2/Users/", s.handleUserByID)
	mux.HandleFunc("/scim/v2/Groups", s.handleGroups)
	mux.HandleFunc("/scim/v2/Groups/", s.handleGroupByID)
}

// ── User Handlers ─────────────────────────────────────────────

func (s *SCIMServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.createUser(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *SCIMServer) handleUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scim/v2/Users/"):]
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "User ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, id)
	case http.MethodPut:
		s.updateUser(w, r, id)
	case http.MethodDelete:
		s.deleteUser(w, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *SCIMServer) listUsers(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*SCIMUser, 0, len(s.users))
	for _, u := range s.users {
		if u.Active {
			users = append(users, u)
		}
	}

	resp := SCIMListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: len(users),
		StartIndex:   1,
		ItemsPerPage: len(users),
		Resources:    users,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *SCIMServer) createUser(w http.ResponseWriter, r *http.Request) {
	var user SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if user.UserName == "" {
		s.writeError(w, http.StatusBadRequest, "userName is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate userName within tenant
	for _, existing := range s.users {
		if existing.UserName == user.UserName && existing.TenantID == user.TenantID && existing.Active {
			s.writeError(w, http.StatusConflict, "User already exists")
			return
		}
	}

	user.ID = s.generateID()
	user.Active = true
	user.Schemas = []string{scimCoreSchema}
	now := time.Now().UTC()
	user.Meta = SCIMMeta{
		ResourceType: "User",
		Created:      now,
		LastModified: now,
	}

	s.users[user.ID] = &user
	s.writeJSON(w, http.StatusCreated, user)
}

func (s *SCIMServer) getUser(w http.ResponseWriter, id string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[id]
	if !ok {
		s.writeError(w, http.StatusNotFound, "User not found")
		return
	}
	s.writeJSON(w, http.StatusOK, user)
}

func (s *SCIMServer) updateUser(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.users[id]
	if !ok {
		s.writeError(w, http.StatusNotFound, "User not found")
		return
	}

	var updated SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Preserve immutable fields
	updated.ID = existing.ID
	updated.Meta.Created = existing.Meta.Created
	updated.Meta.LastModified = time.Now().UTC()
	updated.Meta.ResourceType = "User"
	updated.Schemas = []string{scimCoreSchema}

	s.users[id] = &updated
	s.writeJSON(w, http.StatusOK, updated)
}

func (s *SCIMServer) deleteUser(w http.ResponseWriter, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		s.writeError(w, http.StatusNotFound, "User not found")
		return
	}

	// Soft delete: deactivate, don't remove
	user.Active = false
	user.Meta.LastModified = time.Now().UTC()
	w.WriteHeader(http.StatusNoContent)
}

// ── Group Handlers ────────────────────────────────────────────

func (s *SCIMServer) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listGroups(w)
	case http.MethodPost:
		s.createGroup(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *SCIMServer) handleGroupByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/scim/v2/Groups/"):]
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "Group ID required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getGroup(w, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *SCIMServer) listGroups(w http.ResponseWriter) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make([]*SCIMGroup, 0, len(s.groups))
	for _, g := range s.groups {
		groups = append(groups, g)
	}

	resp := SCIMListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: len(groups),
		StartIndex:   1,
		ItemsPerPage: len(groups),
		Resources:    groups,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *SCIMServer) createGroup(w http.ResponseWriter, r *http.Request) {
	var group SCIMGroup
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	group.ID = s.generateID()
	group.Schemas = []string{scimGroupSchema}
	now := time.Now().UTC()
	group.Meta = SCIMMeta{
		ResourceType: "Group",
		Created:      now,
		LastModified: now,
	}

	s.groups[group.ID] = &group
	s.writeJSON(w, http.StatusCreated, group)
}

func (s *SCIMServer) getGroup(w http.ResponseWriter, id string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	group, ok := s.groups[id]
	if !ok {
		s.writeError(w, http.StatusNotFound, "Group not found")
		return
	}
	s.writeJSON(w, http.StatusOK, group)
}

// ── Helpers ───────────────────────────────────────────────────

func (s *SCIMServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func (s *SCIMServer) writeError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(SCIMError{ //nolint:errcheck
		Schemas: []string{scimErrorSchema},
		Detail:  detail,
		Status:  fmt.Sprintf("%d", status),
	})
}
