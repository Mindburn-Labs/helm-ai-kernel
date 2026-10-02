package siwc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrStorage = errors.New("ChatGPT local credential storage is unavailable or not private")
var ErrHostIdentity = errors.New("unsupported local ChatGPT host identity; preserve this store and use a new --store directory to register again")
var accountPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Account is safe connection metadata. Issuer/subject/client identify the
// external registration, not a HELM tenant, member or delegation authority.
type Account struct {
	ID                          string    `json:"id"`
	Issuer                      string    `json:"issuer"`
	Subject                     string    `json:"subject"`
	ClientID                    string    `json:"client_id"`
	HostID                      string    `json:"host_id"`
	Generation                  string    `json:"generation"`
	Email                       string    `json:"email,omitempty"`
	Scopes                      []string  `json:"scopes,omitempty"`
	ExpiresAt                   time.Time `json:"expires_at,omitempty"`
	SignedIn                    bool      `json:"signed_in"`
	PlanUse                     bool      `json:"plan_use"`
	RemoteRevocationUnconfirmed bool      `json:"remote_revocation_unconfirmed,omitempty"`
	RenewalPending              bool      `json:"renewal_pending,omitempty"`
}

type record struct {
	Account
	AccessToken    string           `json:"access_token,omitempty"`
	RefreshToken   string           `json:"refresh_token,omitempty"`
	IDToken        string           `json:"id_token,omitempty"`
	PendingRefresh *refreshRotation `json:"pending_refresh,omitempty"`
}

type refreshRotation struct {
	Tokens        tokenResponse `json:"tokens"`
	ReceivedAt    time.Time     `json:"received_at"`
	CheckIdentity bool          `json:"check_identity"`
}

// An issued but not yet validated registration is not an Account and grants
// no inference authority. Its ID survives a failed authorization-code exchange.
type incompleteRegistration struct {
	ClientID string `json:"client_id,omitempty"`
	Issuer   string `json:"issuer"`
	HostID   string `json:"host_id"`
}

func (*record) String() string   { return "<ChatGPT credential record: redacted>" }
func (*record) GoString() string { return "<ChatGPT credential record: redacted>" }

// Reference pins a selected local registration. Callers must first resolve
// current owner, membership and consent through CP's Connection authority.
// A reference, possession of this file, and a valid ID token grant no HELM
// mandate. Refresh preserves the generation; reconnect/sign-out invalidate it.
type Reference struct {
	ID         string `json:"id"`
	HostID     string `json:"host_id"`
	Generation string `json:"generation"`
}

type Store struct{ dir, hostID string }

func OpenStore(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, ErrStorage
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, ErrStorage
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return nil, ErrStorage
	}
	s := &Store{dir: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := s.lock(ctx, "host")
	if err != nil {
		return nil, err
	}
	defer unlock()
	var host struct {
		ID string `json:"host_id"`
	}
	err = s.read("host.json", &host)
	if errors.Is(err, os.ErrNotExist) {
		var id uuid.UUID
		id, err = uuid.NewRandom()
		if err == nil {
			host.ID = id.URN()
			err = s.write("host.json", host)
		}
	}
	if err != nil {
		return nil, ErrStorage
	}
	// HELM selects the documented UUIDv4 URN host option. Never rewrite a
	// persisted host: it binds an issued client and its existing credentials.
	id, err := uuid.Parse(host.ID)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || host.ID != id.URN() {
		return nil, ErrHostIdentity
	}
	s.hostID = host.ID
	return s, nil
}

func (s *Store) read(name string, target any) error {
	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) || info.Size() > maxResponseBytes {
		return ErrStorage
	}
	f, err := os.Open(path) // #nosec G304 -- names are fixed or validated account hashes in a private operator-selected directory
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = f.Close() }()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return ErrStorage
	}
	b, err := io.ReadAll(io.LimitReader(f, maxResponseBytes+1))
	if err != nil || len(b) > maxResponseBytes || json.Unmarshal(b, target) != nil {
		return ErrStorage
	}
	return nil
}

func (s *Store) write(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxResponseBytes {
		return ErrStorage
	}
	f, err := os.CreateTemp(s.dir, ".credential-")
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrStorage
	}
	if err := os.Rename(f.Name(), filepath.Join(s.dir, name)); err != nil {
		return ErrStorage
	}
	directory, err := os.Open(s.dir) // #nosec G304 -- private operator-selected credential directory
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return ErrStorage
	}
	return nil
}

func (s *Store) load(id string) (*record, error) {
	if !accountPattern.MatchString(id) {
		return nil, ErrIdentity
	}
	var r record
	if err := s.read("account-"+id+".json", &r); err != nil {
		return nil, err
	}
	if r.ID != id || r.HostID != s.hostID || !validClientID(r.ClientID) || r.Subject == "" || r.Issuer == "" ||
		accountID(r.Issuer, r.ClientID, r.Subject) != id || r.Generation == "" {
		return nil, ErrStorage
	}
	return &r, nil
}

// Accounts returns metadata, including signed-out registrations retained for
// reauthorization. It never returns credentials or an inference bearer token.
func (s *Store) Accounts(ctx context.Context) ([]Account, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, ErrStorage
	}
	var accounts []Account
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "account-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "account-"), ".json")
		unlock, err := s.lock(ctx, id)
		if err != nil {
			return nil, err
		}
		r, err := s.load(id)
		unlock()
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, r.Account)
		if len(accounts) > 100 {
			return nil, ErrStorage
		}
	}
	slices.SortFunc(accounts, func(a, b Account) int { return strings.Compare(a.ID, b.ID) })
	return accounts, nil
}

// Login starts the literal loopback listener before showing the authorization
// URL. A new account has an empty selectedID. A concurrent logout/reconnect
// wins over this pending flow; callback completion cannot resurrect its tokens.
func (s *Store) Login(ctx context.Context, c *Client, selectedID string, showURL func(string) error) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var previous *record
	registeredClient := ""
	if selectedID == "" {
		unlock, err := s.lock(ctx, "registration")
		if err != nil {
			return Account{}, err
		}
		defer unlock()
		var registration incompleteRegistration
		if err := s.read("registration.json", &registration); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Account{}, err
		} else if err == nil {
			if registration.HostID != s.hostID || registration.Issuer != c.issuer || (registration.ClientID != "" && !validClientID(registration.ClientID)) {
				return Account{}, ErrStorage
			}
			registeredClient = registration.ClientID
			if registeredClient != "" {
				// A crash may leave the registration after the validated account
				// was committed. Retire only that proven completed registration.
				accounts, err := s.Accounts(ctx)
				if err != nil {
					return Account{}, err
				}
				for _, account := range accounts {
					if account.ClientID == registeredClient && account.Issuer == c.issuer && account.HostID == s.hostID {
						if err := s.write("registration.json", incompleteRegistration{HostID: s.hostID, Issuer: c.issuer}); err != nil {
							return Account{}, err
						}
						registeredClient = ""
						break
					}
				}
			}
		}
	}
	if selectedID != "" {
		unlock, err := s.lock(ctx, selectedID)
		if err != nil {
			return Account{}, err
		}
		previous, err = s.load(selectedID)
		unlock()
		if err != nil {
			return Account{}, err
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return Account{}, ErrUnavailable
	}
	defer func() { _ = listener.Close() }()
	callback := "http://" + listener.Addr().String() + callbackPath
	p, authorizationURL, err := c.begin(s.hostID, callback, previous, registeredClient)
	if err != nil {
		return Account{}, err
	}
	completed := make(chan url.Values, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if r.Method != http.MethodGet || r.Host != listener.Addr().String() || r.URL.Path != callbackPath || len(r.URL.RawQuery) > 16<<10 {
			http.Error(w, "Invalid sign-in callback", http.StatusBadRequest)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || !p.matchesState(q) {
			http.Error(w, "Invalid sign-in callback", http.StatusBadRequest)
			return
		}
		select {
		case completed <- q:
			_, _ = io.WriteString(w, "Return to HELM to see the sign-in result. You may close this tab.")
		default:
			http.Error(w, "Sign-in callback already received", http.StatusConflict)
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	defer func() { _ = server.Close() }()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()
	if err := showURL(authorizationURL); err != nil {
		return Account{}, err
	}
	var q url.Values
	select {
	case q = <-completed:
	case <-ctx.Done():
		return Account{}, ctx.Err()
	case <-serverErr:
		return Account{}, ErrUnavailable
	}
	_ = server.Close()
	if selectedID == "" {
		clientID, err := p.issuedClient(q)
		if err != nil {
			return Account{}, err
		}
		if err := s.write("registration.json", incompleteRegistration{ClientID: clientID, HostID: s.hostID, Issuer: c.issuer}); err != nil {
			return Account{}, err
		}
	}
	r, err := c.complete(ctx, p, q)
	if err != nil {
		return Account{}, err
	}
	unlock, err := s.lock(ctx, r.ID)
	if err != nil {
		return Account{}, err
	}
	defer unlock()
	current, err := s.load(r.ID)
	if previous == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return Account{}, ErrChanged
		}
	} else if err != nil || current.Generation != previous.Generation {
		return Account{}, ErrChanged
	}
	if err := s.write("account-"+r.ID+".json", r); err != nil {
		return Account{}, err
	}
	if selectedID == "" {
		if err := s.write("registration.json", incompleteRegistration{HostID: s.hostID, Issuer: c.issuer}); err != nil {
			return Account{}, err
		}
	}
	return r.Account, nil
}

// AccessToken is custody only: the model gateway calls it after CP's current
// owner-bound Connection authorization and ordinary HELM admission. It never
// selects a default account or falls back to a provider API key.
func (s *Store) AccessToken(ctx context.Context, c *Client, ref Reference) (string, error) {
	unlock, err := s.lock(ctx, ref.ID)
	if err != nil {
		return "", err
	}
	defer unlock()
	r, err := s.load(ref.ID)
	if err != nil {
		return "", err
	}
	if ref.HostID != s.hostID || ref.Generation != r.Generation {
		return "", ErrChanged
	}
	if !r.SignedIn || r.Issuer != c.issuer {
		return "", ErrReauthorize
	}
	if !r.PlanUse && r.PendingRefresh == nil {
		return "", ErrPermission
	}
	refresh := func() error {
		err := c.refresh(ctx, r, func() error { return s.write("account-"+r.ID+".json", r) })
		if err != nil {
			if errors.Is(err, ErrReauthorize) || errors.Is(err, ErrIdentity) {
				r.clearTokens()
				if writeErr := s.write("account-"+r.ID+".json", r); writeErr != nil {
					return writeErr
				}
			}
		}
		return err
	}
	wasPending := r.PendingRefresh != nil
	if wasPending || !c.now().Add(time.Minute).Before(r.ExpiresAt) {
		if err := refresh(); err != nil {
			return "", err
		}
	}
	if wasPending && !c.now().Before(r.ExpiresAt) {
		// A long key-service outage can outlast the quarantined access token.
		// Its now-verified replacement refresh token remains renewable.
		if err := refresh(); err != nil {
			return "", err
		}
	}
	if !c.now().Before(r.ExpiresAt) {
		return "", ErrUnavailable
	}
	if !r.PlanUse {
		return "", ErrPermission
	}
	return r.AccessToken, nil
}

// Logout always clears local tokens. Its boolean states whether remote
// revocation was confirmed; failure must remain visible to the user.
func (s *Store) Logout(ctx context.Context, c *Client, ref Reference) (bool, error) {
	unlock, err := s.lock(ctx, ref.ID)
	if err != nil {
		return false, err
	}
	defer unlock()
	r, err := s.load(ref.ID)
	if err != nil {
		return false, err
	}
	if ref.HostID != s.hostID || ref.Generation != r.Generation {
		return false, ErrChanged
	}
	confirmed := !r.RemoteRevocationUnconfirmed
	if r.RefreshToken != "" {
		confirmed = c.revoke(ctx, r) == nil
	}
	r.clearTokens()
	r.RemoteRevocationUnconfirmed = !confirmed
	r.Generation, err = randomValue()
	if err != nil {
		return false, err
	}
	if err := s.write("account-"+r.ID+".json", r); err != nil {
		return false, err
	}
	return confirmed, nil
}

func (r *record) clearTokens() {
	r.AccessToken, r.RefreshToken, r.IDToken = "", "", ""
	r.Scopes, r.ExpiresAt, r.SignedIn, r.PlanUse = nil, time.Time{}, false, false
	r.PendingRefresh, r.RenewalPending = nil, false
}

func (a Account) Reference() Reference {
	return Reference{ID: a.ID, HostID: a.HostID, Generation: a.Generation}
}

func (s *Store) lock(ctx context.Context, name string) (func(), error) {
	if name != "host" && name != "registration" && !accountPattern.MatchString(name) {
		return nil, fmt.Errorf("%w: invalid account reference", ErrIdentity)
	}
	return lockFile(ctx, filepath.Join(s.dir, name+".lock"))
}
