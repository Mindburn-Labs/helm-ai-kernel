// quantum_posture: this package implements the RFC 9421 wire format and signs
// with classical Ed25519 from the standard library. It introduces no
// cryptographic control of its own and makes no hybrid or post-quantum claim;
// the algorithm agility to add one lives in the alg field of the signature
// parameters, not here.

// Package httpsig implements HTTP Message Signatures (RFC 9421) for the subset
// HELM needs to identify itself as a governed agent to a third-party origin.
//
// The IETF Web Bot Auth protocol (draft-ietf-webbotauth-httpsig-protocol) builds
// directly on this format: a bot signs @authority, @method and @path with a key
// it publishes, and a verifier such as Cloudflare checks the signature against
// that published key. This package is the format half of that, and nothing more.
//
// It is deliberately a library with no caller yet. HELM has no governed
// third-party web fetch today, and a signer wired into a path that does not exist
// would be guesswork. What it does have is a published test vector: RFC 9421
// Appendix B.2.6 gives an exact signature base, key and signature for Ed25519, so
// this implementation can be proven correct now rather than assumed correct later.
// See HELM-711.
package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Derived component identifiers from RFC 9421 section 2.2. These are the three
// Web Bot Auth requires, plus signature-agent, which the protocol draft adds to
// carry the directory the verifier should fetch the key from.
const (
	ComponentMethod         = "@method"
	ComponentAuthority      = "@authority"
	ComponentPath           = "@path"
	ComponentSignatureAgent = "signature-agent"
)

// Params are the signature parameters that accompany a signature: which
// components it covers and the metadata a verifier needs to reproduce the base.
type Params struct {
	// Components are covered in the order given. Order is part of the signature
	// base, so it is preserved rather than sorted.
	Components []string
	// Created is a Unix timestamp. Zero omits the parameter.
	Created int64
	// Expires is a Unix timestamp. Zero omits the parameter.
	Expires int64
	// KeyID identifies the key a verifier should use.
	KeyID string
	// Alg names the algorithm. RFC 9421 allows omitting it when the key implies
	// the algorithm; Web Bot Auth expects "ed25519".
	Alg string
	// Nonce is optional replay protection. Empty omits the parameter.
	Nonce string
	// Tag is optional application context. Empty omits the parameter.
	Tag string
}

// SignatureBase builds the exact byte string RFC 9421 section 2.5 signs.
//
// The format is unforgiving by design: one component per line, the identifier
// quoted and lowercased, a colon and a single space, then the value, with the
// @signature-params line last and no trailing newline after it. A verifier
// rebuilds this string from the request it received, so any deviation is a
// verification failure rather than a tolerated variation.
func SignatureBase(r *http.Request, p Params) (string, error) {
	if len(p.Components) == 0 {
		return "", fmt.Errorf("httpsig: at least one covered component is required")
	}
	var b strings.Builder
	for _, component := range p.Components {
		name := strings.ToLower(strings.TrimSpace(component))
		value, err := componentValue(r, name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%q: %s\n", name, value)
	}
	fmt.Fprintf(&b, "%q: %s", "@signature-params", p.serialize())
	return b.String(), nil
}

// componentValue resolves one covered component against the request.
func componentValue(r *http.Request, name string) (string, error) {
	switch name {
	case ComponentMethod:
		// Canonicalised as the method string, which HTTP already requires to be
		// uppercase; it is not lowercased here.
		return r.Method, nil
	case ComponentAuthority:
		return canonicalAuthority(r)
	case ComponentPath:
		path := r.URL.EscapedPath()
		if path == "" {
			// RFC 9421: an empty path is canonicalised as "/", so a request to
			// https://example.com and one to https://example.com/ sign the same.
			return "/", nil
		}
		return path, nil
	default:
		if strings.HasPrefix(name, "@") {
			return "", fmt.Errorf("httpsig: unsupported derived component %q", name)
		}
		values := r.Header.Values(http.CanonicalHeaderKey(name))
		if len(values) == 0 {
			return "", fmt.Errorf("httpsig: covered header %q is not present on the request", name)
		}
		// RFC 9421 section 2.1: multiple field values are combined with ", " after
		// each is stripped of leading and trailing whitespace.
		trimmed := make([]string, 0, len(values))
		for _, v := range values {
			trimmed = append(trimmed, strings.TrimSpace(v))
		}
		return strings.Join(trimmed, ", "), nil
	}
}

// canonicalAuthority returns the host and, when it is not the scheme's default,
// the port. Lowercased, because a verifier that received the same request through
// a different proxy must derive the same string.
func canonicalAuthority(r *http.Request) (string, error) {
	authority := r.Host
	if authority == "" && r.URL != nil {
		authority = r.URL.Host
	}
	if authority == "" {
		return "", fmt.Errorf("httpsig: request has no authority to sign")
	}
	authority = strings.ToLower(authority)
	host, port, err := splitHostPort(authority)
	if err != nil {
		return authority, nil
	}
	scheme := "https"
	if r.URL != nil && r.URL.Scheme != "" {
		scheme = strings.ToLower(r.URL.Scheme)
	} else if r.TLS == nil {
		scheme = "http"
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return host, nil
	}
	return authority, nil
}

func splitHostPort(authority string) (host, port string, err error) {
	idx := strings.LastIndex(authority, ":")
	if idx < 0 || strings.Contains(authority[idx:], "]") {
		return authority, "", fmt.Errorf("no port")
	}
	return authority[:idx], authority[idx+1:], nil
}

// serialize renders the @signature-params value: the covered component list
// followed by the parameters, in the order RFC 9421 examples use.
func (p Params) serialize() string {
	quoted := make([]string, 0, len(p.Components))
	for _, c := range p.Components {
		quoted = append(quoted, strconv.Quote(strings.ToLower(strings.TrimSpace(c))))
	}
	out := "(" + strings.Join(quoted, " ") + ")"
	if p.Created != 0 {
		out += ";created=" + strconv.FormatInt(p.Created, 10)
	}
	if p.Expires != 0 {
		out += ";expires=" + strconv.FormatInt(p.Expires, 10)
	}
	if p.KeyID != "" {
		out += ";keyid=" + strconv.Quote(p.KeyID)
	}
	if p.Alg != "" {
		out += ";alg=" + strconv.Quote(p.Alg)
	}
	if p.Nonce != "" {
		out += ";nonce=" + strconv.Quote(p.Nonce)
	}
	if p.Tag != "" {
		out += ";tag=" + strconv.Quote(p.Tag)
	}
	return out
}

// Sign signs the request in place, setting Signature-Input and Signature under
// the given label. The request is not otherwise modified: no body is read, and no
// header the caller did not already set is added.
func Sign(r *http.Request, label string, key ed25519.PrivateKey, p Params) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("httpsig: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	if strings.TrimSpace(label) == "" {
		return fmt.Errorf("httpsig: a signature label is required")
	}
	base, err := SignatureBase(r, p)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, []byte(base))
	r.Header.Set("Signature-Input", label+"="+p.serialize())
	r.Header.Set("Signature", label+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

// Verify checks the signature under the given label against the request.
//
// It rebuilds the base from the request rather than trusting the sender's, which
// is the entire point: a signature over a base the verifier did not derive proves
// nothing about the request that arrived.
func Verify(r *http.Request, label string, key ed25519.PublicKey, p Params) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("httpsig: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
	}
	raw := r.Header.Get("Signature")
	if raw == "" {
		return fmt.Errorf("httpsig: request carries no Signature header")
	}
	encoded, err := signatureForLabel(raw, label)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("httpsig: signature for %q is not valid base64: %w", label, err)
	}
	base, err := SignatureBase(r, p)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, []byte(base), signature) {
		return fmt.Errorf("httpsig: signature %q does not verify over the derived base", label)
	}
	return nil
}

// signatureForLabel extracts one label's value from a Signature header that may
// carry several.
func signatureForLabel(header, label string) (string, error) {
	for _, entry := range strings.Split(header, ",") {
		entry = strings.TrimSpace(entry)
		name, value, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(name) != label {
			continue
		}
		value = strings.TrimSpace(value)
		if !strings.HasPrefix(value, ":") || !strings.HasSuffix(value, ":") || len(value) < 2 {
			return "", fmt.Errorf("httpsig: signature for %q is not a byte sequence", label)
		}
		return value[1 : len(value)-1], nil
	}
	return "", fmt.Errorf("httpsig: Signature header carries no entry labelled %q", label)
}

// DirectoryEntry is one key as published at
// /.well-known/http-message-signatures-directory, the location Web Bot Auth
// verifiers fetch to resolve a keyid.
type DirectoryEntry struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	PublicKey string `json:"x"`
}

// Directory is the published key set.
type Directory struct {
	Keys []DirectoryEntry `json:"keys"`
}

// NewDirectory builds a directory from public keys, keyed by identifier.
//
// Keys are emitted in sorted key-id order so the document is byte-stable: a
// directory that reshuffles on every request defeats caching and makes a
// mismatch impossible to diagnose.
func NewDirectory(keys map[string]ed25519.PublicKey) (Directory, error) {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		if strings.TrimSpace(id) == "" {
			return Directory{}, fmt.Errorf("httpsig: a directory key id cannot be blank")
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	directory := Directory{Keys: make([]DirectoryEntry, 0, len(ids))}
	for _, id := range ids {
		key := keys[id]
		if len(key) != ed25519.PublicKeySize {
			return Directory{}, fmt.Errorf("httpsig: key %q is not an ed25519 public key", id)
		}
		directory.Keys = append(directory.Keys, DirectoryEntry{
			KeyID:     id,
			KeyType:   "OKP",
			Curve:     "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(key),
		})
	}
	return directory, nil
}

// SignatureAgentURL validates a signature-agent value: the URL a verifier is told
// to fetch the directory from. It must be an absolute HTTPS URL, because a
// verifier following it over plain HTTP would be trusting the network to tell it
// which key signed the request.
func SignatureAgentURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("httpsig: signature-agent is not a URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("httpsig: signature-agent must be https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("httpsig: signature-agent must be absolute")
	}
	return parsed.String(), nil
}
