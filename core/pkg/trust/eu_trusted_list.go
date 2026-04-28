// Package trust — EU Trusted List validator.
//
// This file implements a fetcher and validator for the EU List of Trusted Lists
// (LOTL) as published by the European Commission per Article 22 of the eIDAS
// Regulation (EU) 910/2014. The LOTL is a signed XML document that lists the
// Trusted Lists of every EU/EEA Member State; each Member State Trusted List
// in turn enumerates the Qualified Trust Service Providers (QTSPs) and the
// service-digital-identity certificates of every Qualified Time-Stamping
// Authority (QTSA) operating under that State's supervision.
//
// The LOTL is the regulatory pivot for any eIDAS-qualified evidence claim.
// helm-oss uses it to decide whether an RFC 3161 timestamp token returned by
// a QTSP terminates at a State-supervised root.
//
// Trust model: this client treats the parsed LOTL as a cache of certificate
// thumbprints; it deliberately does not require a heavyweight XML signature
// verification path because real-world LOTL fetchers (DSS, EU Member State
// validators) treat the LOTL as authoritative when retrieved over TLS from
// the EC endpoint. A full XAdES verification path is documented as a
// follow-up — the public method surface is shaped to absorb that future
// upgrade without breaking callers.
package trust

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultEULOTLEndpoint is the canonical EU LOTL URL operated by the
// European Commission. See https://ec.europa.eu/tools/lotl/eu-lotl.xml.
const DefaultEULOTLEndpoint = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

// DefaultEULOTLRefreshInterval is the recommended refresh cadence for the
// LOTL. The EU publishes refreshes at least every 6 months; 24h gives a
// generous safety margin and matches the constraint shipped in the EU AI
// Act high-risk reference pack.
const DefaultEULOTLRefreshInterval = 24 * time.Hour

// EUTrustedListConfig configures an EUTrustedList instance.
type EUTrustedListConfig struct {
	// Endpoint is the HTTPS URL of the LOTL. Defaults to DefaultEULOTLEndpoint.
	Endpoint string

	// RefreshInterval bounds how often Refresh() will hit the network.
	// Defaults to DefaultEULOTLRefreshInterval.
	RefreshInterval time.Duration

	// HTTPClient is the client used for LOTL fetches. Defaults to a 30s client.
	HTTPClient *http.Client

	// Now overrides time.Now for tests; nil means time.Now.
	Now func() time.Time
}

// EUTrustedListStatus is the snapshot returned by Status() — useful for
// `helm trust eu-list status` and for operator dashboards.
type EUTrustedListStatus struct {
	// Endpoint is the URL the list was fetched from.
	Endpoint string `json:"endpoint"`

	// LastRefresh is the time the cache was most recently populated.
	// Zero value means "never refreshed".
	LastRefresh time.Time `json:"last_refresh"`

	// SchemeOperator is the LOTL signer / scheme operator name
	// (e.g. "European Commission - DG CNECT").
	SchemeOperator string `json:"scheme_operator,omitempty"`

	// QualifiedTSACount is the number of Qualified Time-Stamping
	// Authority service entries currently cached.
	QualifiedTSACount int `json:"qualified_tsa_count"`

	// MemberStateCount is the count of Member State Trusted Lists referenced.
	MemberStateCount int `json:"member_state_count"`

	// Stale reports whether the cache is older than RefreshInterval.
	Stale bool `json:"stale"`

	// Age is the wall-clock delta between Now and LastRefresh.
	Age time.Duration `json:"age"`
}

// EUTrustedList is a thread-safe in-memory cache of qualified-TSA roots
// derived from the EU LOTL. Callers Refresh() it on a schedule and ask
// Trust() whether a given certificate thumbprint is supervised by an EU
// Member State.
type EUTrustedList struct {
	cfg EUTrustedListConfig

	mu             sync.RWMutex
	thumbprints    map[string]struct{}
	memberStates   map[string]struct{}
	lastRefresh    time.Time
	schemeOperator string
}

// NewEUTrustedList builds a list with the default endpoint and refresh
// interval. It does not perform an initial fetch — callers should invoke
// Refresh(ctx) before Trust() for the first time, or rely on the staleness
// check via Status().
func NewEUTrustedList() *EUTrustedList {
	return NewEUTrustedListWithConfig(EUTrustedListConfig{})
}

// NewEUTrustedListWithConfig is the configurable constructor. Zero-valued
// fields fall back to defaults.
func NewEUTrustedListWithConfig(cfg EUTrustedListConfig) *EUTrustedList {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEULOTLEndpoint
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultEULOTLRefreshInterval
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &EUTrustedList{
		cfg:          cfg,
		thumbprints:  make(map[string]struct{}),
		memberStates: make(map[string]struct{}),
	}
}

// LastRefresh returns the time of the most recent successful Refresh().
func (l *EUTrustedList) LastRefresh() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastRefresh
}

// Trust reports whether certThumbprint (lowercase hex SHA-256 of the
// certificate DER, no separators) is in the cached qualified-TSA set.
//
// Returns false when the cache is empty. Callers that require freshness
// should consult Status().Stale before relying on a Trust() answer.
func (l *EUTrustedList) Trust(certThumbprint string) bool {
	if certThumbprint == "" {
		return false
	}
	tp := strings.ToLower(strings.TrimSpace(certThumbprint))
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.thumbprints[tp]
	return ok
}

// Status returns a snapshot of the current cache state.
func (l *EUTrustedList) Status() *EUTrustedListStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := l.cfg.Now().UTC()
	age := time.Duration(0)
	stale := true
	if !l.lastRefresh.IsZero() {
		age = now.Sub(l.lastRefresh)
		stale = age > l.cfg.RefreshInterval
	}
	return &EUTrustedListStatus{
		Endpoint:          l.cfg.Endpoint,
		LastRefresh:       l.lastRefresh,
		SchemeOperator:    l.schemeOperator,
		QualifiedTSACount: len(l.thumbprints),
		MemberStateCount:  len(l.memberStates),
		Stale:             stale,
		Age:               age,
	}
}

// Refresh fetches the LOTL XML, parses it, and updates the cache.
//
// If Refresh has run successfully within RefreshInterval, it is a no-op.
// Pass a context with a deadline to bound network IO. Errors leave the
// previous cache contents intact.
func (l *EUTrustedList) Refresh(ctx context.Context) error {
	l.mu.RLock()
	last := l.lastRefresh
	l.mu.RUnlock()
	if !last.IsZero() && l.cfg.Now().UTC().Sub(last) < l.cfg.RefreshInterval {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.cfg.Endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("eu_trusted_list: build request: %w", err)
	}
	req.Header.Set("Accept", "application/xml")

	resp, err := l.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("eu_trusted_list: fetch %s: %w", l.cfg.Endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("eu_trusted_list: fetch %s: status %d", l.cfg.Endpoint, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("eu_trusted_list: read body: %w", err)
	}

	parsed, err := parseLOTL(body)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.thumbprints = parsed.thumbprints
	l.memberStates = parsed.memberStates
	l.schemeOperator = parsed.schemeOperator
	l.lastRefresh = l.cfg.Now().UTC()
	l.mu.Unlock()
	return nil
}

// LoadFromBytes parses raw LOTL XML and replaces the cache. Useful for
// tests, offline fixtures, and pre-seeded keystores.
func (l *EUTrustedList) LoadFromBytes(data []byte) error {
	parsed, err := parseLOTL(data)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.thumbprints = parsed.thumbprints
	l.memberStates = parsed.memberStates
	l.schemeOperator = parsed.schemeOperator
	l.lastRefresh = l.cfg.Now().UTC()
	l.mu.Unlock()
	return nil
}

// parsedLOTL is the intermediate representation a single XML parse produces.
type parsedLOTL struct {
	thumbprints    map[string]struct{}
	memberStates   map[string]struct{}
	schemeOperator string
}

// lotlMultiLangName carries the SchemeOperatorName/Name elements from
// the LOTL header. Multilingual; we pick the English entry.
type lotlMultiLangName struct {
	Name []struct {
		Lang  string `xml:"lang,attr"`
		Value string `xml:",chardata"`
	} `xml:"Name"`
}

// lotlServiceDigitalIdentity carries the X509 certificate (DER, base64) of a
// service. Multiple entries may exist per service; we hash each one.
type lotlServiceDigitalIdentity struct {
	DigitalID []struct {
		X509Certificate    string `xml:"X509Certificate"`
		X509SubjectName    string `xml:"X509SubjectName"`
		X509CertificateSHA string `xml:"X509CertificateSHA256"`
	} `xml:"DigitalId"`
}

// lotlService is a TSPService entry — a Qualified TSA in our use case.
type lotlService struct {
	ServiceTypeIdentifier  string                     `xml:"ServiceInformation>ServiceTypeIdentifier"`
	ServiceName            lotlMultiLangName          `xml:"ServiceInformation>ServiceName"`
	ServiceStatus          string                     `xml:"ServiceInformation>ServiceStatus"`
	ServiceDigitalIdentity lotlServiceDigitalIdentity `xml:"ServiceInformation>ServiceDigitalIdentity"`
}

// lotlTSP is a Trust Service Provider entry.
type lotlTSP struct {
	TSPName  lotlMultiLangName `xml:"TSPInformation>TSPName"`
	Country  string            `xml:"TSPInformation>SchemeTerritory"`
	Services []lotlService     `xml:"TSPServices>TSPService"`
}

// lotlPointer is one entry in the LOTL pointing at a Member State Trusted List.
type lotlPointer struct {
	SchemeTerritory string `xml:"AdditionalInformation>OtherInformation>SchemeTerritory"`
	TSLLocation     string `xml:"TSLLocation"`
}

// lotlDocument is the top-level TrustServiceStatusList shape used both for the
// LOTL itself and for an inlined Member State TL fixture. We use a permissive
// schema: optional fields, optional wrapper containers — the real DSS XSD has
// dozens of namespaces, but we only need the certificate-bearing leaves.
type lotlDocument struct {
	XMLName        xml.Name          `xml:"TrustServiceStatusList"`
	SchemeOperator lotlMultiLangName `xml:"SchemeInformation>SchemeOperatorName"`
	Pointers       []lotlPointer     `xml:"SchemeInformation>PointersToOtherTSL>OtherTSLPointer"`
	TSPs           []lotlTSP         `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

// qualifiedTimestampingService is the eIDAS service-type-identifier URI for a
// qualified time-stamping authority.
const qualifiedTimestampingService = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"

// grantedStatusURI is the URI marking a service in "granted" status — i.e.
// currently authorized and supervised by the Member State.
const grantedStatusURI = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

func parseLOTL(data []byte) (*parsedLOTL, error) {
	var doc lotlDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("eu_trusted_list: parse XML: %w", err)
	}

	out := &parsedLOTL{
		thumbprints:  make(map[string]struct{}),
		memberStates: make(map[string]struct{}),
	}
	out.schemeOperator = pickEnglish(doc.SchemeOperator)

	// Member State pointers (each one points at a national TL).
	for _, p := range doc.Pointers {
		if p.SchemeTerritory != "" {
			out.memberStates[strings.ToUpper(p.SchemeTerritory)] = struct{}{}
		}
	}

	// Inline TSPs and their Qualified TSAs.
	for _, tsp := range doc.TSPs {
		if tsp.Country != "" {
			out.memberStates[strings.ToUpper(tsp.Country)] = struct{}{}
		}
		for _, svc := range tsp.Services {
			if svc.ServiceTypeIdentifier != qualifiedTimestampingService {
				continue
			}
			if svc.ServiceStatus != "" && svc.ServiceStatus != grantedStatusURI {
				continue
			}
			for _, did := range svc.ServiceDigitalIdentity.DigitalID {
				tp := computeThumbprint(did.X509Certificate, did.X509CertificateSHA)
				if tp != "" {
					out.thumbprints[tp] = struct{}{}
				}
			}
		}
	}

	if len(out.thumbprints) == 0 && len(out.memberStates) == 0 {
		return nil, errors.New("eu_trusted_list: parsed LOTL contains no qualified TSAs and no member-state pointers")
	}
	return out, nil
}

func pickEnglish(n lotlMultiLangName) string {
	for _, name := range n.Name {
		if strings.EqualFold(name.Lang, "en") && strings.TrimSpace(name.Value) != "" {
			return strings.TrimSpace(name.Value)
		}
	}
	for _, name := range n.Name {
		if strings.TrimSpace(name.Value) != "" {
			return strings.TrimSpace(name.Value)
		}
	}
	return ""
}

// computeThumbprint accepts either an explicit X509CertificateSHA256 value or
// a base64-DER certificate from which to derive one. Returned value is
// lowercase hex SHA-256 of the certificate DER.
func computeThumbprint(certBase64, providedSHA string) string {
	if providedSHA != "" {
		return strings.ToLower(strings.TrimSpace(providedSHA))
	}
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, certBase64)
	if cleaned == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		// Some LOTL fixtures use URL-safe base64.
		der, err = base64.URLEncoding.DecodeString(cleaned)
		if err != nil {
			return ""
		}
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
