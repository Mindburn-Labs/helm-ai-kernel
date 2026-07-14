package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// readSetupLifecycleReceiptReadOnly opens only an already-existing receipt
// store. Provenance checks must not run migrations, enable WAL, create a
// database, or otherwise change local authority state merely because a user
// asks whether automatic removal is safe.
func readSetupLifecycleReceiptReadOnly(ctx context.Context, dataDir, receiptID string) (*contracts.Receipt, error) {
	receipt, exists, err := inspectSetupLifecycleReceiptReadOnly(ctx, dataDir, receiptID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("lifecycle receipt %q was not found", receiptID)
	}
	return receipt, nil
}

// inspectSetupLifecycleReceiptReadOnly distinguishes a genuinely absent
// receipt from corrupted, legacy, or unreadable durable state. Recovery uses
// it before issuing any signer: a receipt that already exists must be
// re-verified from its own signature profile without opening SQLite writable
// or generating a key for the current environment profile.
func inspectSetupLifecycleReceiptReadOnly(ctx context.Context, dataDir, receiptID string) (*contracts.Receipt, bool, error) {
	if !isSetupLifecycleReceiptID(receiptID) {
		return nil, false, fmt.Errorf("lifecycle receipt id is invalid")
	}
	securedDataDir, err := requireSetupAuthorityDataDir(dataDir)
	if err != nil {
		return nil, false, fmt.Errorf("inspect lifecycle receipt authority state: %w", err)
	}
	database, err := inspectSetupRegularFile(filepath.Join(securedDataDir, "helm.db"))
	if err != nil {
		return nil, false, fmt.Errorf("inspect lifecycle receipt database: %w", err)
	}
	if !database.Exists {
		return nil, false, nil
	}

	// modernc SQLite accepts a file URI. mode=ro ensures this path rejects a
	// missing or legacy database instead of creating or migrating it. Build it
	// as a URI so spaces, #, and query-like characters in a user path cannot
	// change SQLite's connection options.
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(database.Path), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, false, fmt.Errorf("open lifecycle receipt database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return nil, false, fmt.Errorf("open lifecycle receipt database read-only: %w", err)
	}

	var envelope string
	err = db.QueryRowContext(ctx, `SELECT receipt_envelope FROM receipts WHERE receipt_id = ?`, receiptID).Scan(&envelope)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read canonical lifecycle receipt envelope: %w", err)
	}
	if envelope == "" {
		return nil, false, fmt.Errorf("lifecycle receipt %q predates canonical durable receipt envelopes; automatic provenance is unavailable until it is re-established", receiptID)
	}
	decoder := json.NewDecoder(strings.NewReader(envelope))
	decoder.UseNumber()
	var receipt contracts.Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, false, fmt.Errorf("decode canonical lifecycle receipt envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, false, fmt.Errorf("canonical lifecycle receipt envelope has trailing JSON")
		}
		return nil, false, fmt.Errorf("read canonical lifecycle receipt envelope: %w", err)
	}
	canonical, err := canonicalize.JCS(&receipt)
	if err != nil {
		return nil, false, fmt.Errorf("canonicalize lifecycle receipt envelope: %w", err)
	}
	if !bytes.Equal(canonical, []byte(envelope)) {
		return nil, false, fmt.Errorf("lifecycle receipt envelope is not canonical")
	}
	if receipt.ReceiptID != receiptID {
		return nil, false, fmt.Errorf("lifecycle receipt envelope id does not match its database row")
	}
	return &receipt, true, nil
}
