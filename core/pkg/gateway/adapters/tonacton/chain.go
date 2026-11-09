package tonacton

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ChainTx is what the testnet RPC says of one transaction.
type ChainTx struct {
	Found bool
	// Evidence is the RPC answer the verdict rests on.
	Evidence []byte
}

// ChainReader reads TON testnet, independently of the Acton process, to
// establish that a broadcast transaction landed.
type ChainReader interface {
	FindTransaction(ctx context.Context, address, txHashHex string) (ChainTx, error)
}

const maxChainAnswer = 1 << 20

// Toncenter reads a toncenter v2 compatible testnet endpoint.
type Toncenter struct {
	base   string
	client *http.Client
}

// NewToncenter returns a reader for the API root base, which must be https
// (http only on a loopback address).
func NewToncenter(base string) (*Toncenter, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return nil, errors.New("the TON testnet RPC URL is not a URL")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, errors.New("the TON testnet RPC URL must be https (http only on a loopback address)")
	}
	return &Toncenter{base: u.String(), client: &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// FindTransaction lists the account's recent transactions and looks for the hash.
func (t *Toncenter) FindTransaction(ctx context.Context, address, txHashHex string) (ChainTx, error) {
	q := url.Values{"address": {address}, "limit": {"50"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base+"/getTransactions?"+q.Encode(), nil)
	if err != nil {
		return ChainTx{}, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return ChainTx{}, fmt.Errorf("TON testnet RPC: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChainAnswer+1))
	if err != nil || len(body) > maxChainAnswer || resp.StatusCode != http.StatusOK {
		return ChainTx{}, errors.New("TON testnet RPC: the answer is unusable")
	}
	var answer struct {
		OK     bool `json:"ok"`
		Result []struct {
			ID struct {
				Hash string `json:"hash"`
			} `json:"transaction_id"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &answer) != nil || !answer.OK {
		return ChainTx{}, errors.New("TON testnet RPC: the answer is not the expected JSON")
	}
	sum := sha256.Sum256(body)
	for _, tx := range answer.Result {
		if normalizeHash(tx.ID.Hash) == txHashHex {
			return ChainTx{Found: true, Evidence: sum[:]}, nil
		}
	}
	return ChainTx{Found: false, Evidence: sum[:]}, nil
}

// normalizeHash renders a 32-byte hash given as hex or base64 as lower-case hex.
func normalizeHash(h string) string {
	if b, err := hex.DecodeString(h); err == nil && len(b) == 32 {
		return hex.EncodeToString(b)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(h); err == nil && len(b) == 32 {
			return hex.EncodeToString(b)
		}
	}
	return ""
}
