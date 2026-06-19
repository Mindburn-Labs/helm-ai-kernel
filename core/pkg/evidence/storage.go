package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	EvidencePackStorageReceiptSchemaS3       = "helm.evidence.storage.s3-object-lock.v1"
	legacyEvidencePackStorageReceiptSchemaS3 = "helm.evidencepack.storage.s3-object-lock.v1"
)

type EvidencePackStorageReceipt struct {
	SchemaVersion string    `json:"schema_version"`
	StorageType   string    `json:"storage_type"`
	SubjectRoot   string    `json:"subject_root"`
	Bucket        string    `json:"bucket"`
	Key           string    `json:"key"`
	Region        string    `json:"region,omitempty"`
	VersionID     string    `json:"version_id"`
	ETag          string    `json:"etag,omitempty"`
	ObjectHash    string    `json:"object_hash"`
	RetentionMode string    `json:"retention_mode"`
	RetainUntil   time.Time `json:"retain_until"`
	StoredAt      time.Time `json:"stored_at"`
}

var loadS3ObjectLockConfig = config.LoadDefaultConfig

func DefaultStorageReceiptPath(bundlePath string) string {
	return bundlePath + ".storage.json"
}

func WriteStorageReceipt(path string, receipt EvidencePackStorageReceipt) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("storage receipt path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func ReadStorageReceipt(path string) (*EvidencePackStorageReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var receipt EvidencePackStorageReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func StoreArchiveWithS3ObjectLock(ctx context.Context, archivePath, subjectRoot string, cfg EvidencePackSealStorage) (*EvidencePackStorageReceipt, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("S3 storage bucket is required")
	}
	region := firstNonEmpty(cfg.Region, os.Getenv("ARTIFACT_S3_REGION"), os.Getenv("AWS_REGION"), "us-east-1")
	retainUntil := cfg.RetainUntil
	if retainUntil.IsZero() {
		days := cfg.RetentionDays
		if days <= 0 {
			days = 365
		}
		retainUntil = time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	}
	mode := strings.ToUpper(firstNonEmpty(cfg.ObjectLockMode, "COMPLIANCE"))
	if mode != "COMPLIANCE" {
		return nil, fmt.Errorf("customer storage requires COMPLIANCE Object Lock mode, got %s", mode)
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, err
	}
	objectHash := sha256HashString(data)
	key := strings.TrimLeft(cfg.Prefix, "/")
	if key != "" && !strings.HasSuffix(key, "/") {
		key += "/"
	}
	key += strings.TrimSuffix(strings.TrimPrefix(objectHash, "sha256:"), ".tar") + ".tar"

	awsCfg, err := loadS3ObjectLockConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true
		}
	})
	put, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(cfg.Bucket),
		Key:                       aws.String(key),
		Body:                      bytes.NewReader(data),
		ContentType:               aws.String("application/x-tar"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(retainUntil),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 object-lock put failed: %w", err)
	}
	versionID := ""
	if put.VersionId != nil {
		versionID = *put.VersionId
	}
	if strings.TrimSpace(versionID) == "" {
		return nil, fmt.Errorf("s3 object-lock put did not return a version id")
	}
	etag := ""
	if put.ETag != nil {
		etag = strings.Trim(*put.ETag, `"`)
	}
	return &EvidencePackStorageReceipt{
		SchemaVersion: EvidencePackStorageReceiptSchemaS3,
		StorageType:   "s3-object-lock",
		SubjectRoot:   subjectRoot,
		Bucket:        cfg.Bucket,
		Key:           key,
		Region:        region,
		VersionID:     versionID,
		ETag:          etag,
		ObjectHash:    objectHash,
		RetentionMode: mode,
		RetainUntil:   retainUntil.UTC(),
		StoredAt:      time.Now().UTC(),
	}, nil
}

func VerifyStorageReceiptForSeal(seal EvidencePackSeal, profile EvidenceTrustProfile, explicitPath, objectPath string, now time.Time) (string, string, []string) {
	profile = NormalizeEvidenceTrustProfile(profile)
	path := firstNonEmpty(explicitPath, seal.Storage.Receipt)
	if strings.TrimSpace(path) == "" {
		if !profileRequiresExternalTrust(profile) {
			return "local-only", "", nil
		}
		return "missing", "", []string{fmt.Sprintf("%s profile requires storage receipt", profile)}
	}
	receipt, err := ReadStorageReceipt(path)
	if err != nil {
		return "missing", path, []string{fmt.Sprintf("read storage receipt: %v", err)}
	}
	var errs []string
	if receipt.SchemaVersion != EvidencePackStorageReceiptSchemaS3 && receipt.SchemaVersion != legacyEvidencePackStorageReceiptSchemaS3 {
		errs = append(errs, fmt.Sprintf("unsupported storage receipt schema %q", receipt.SchemaVersion))
	}
	if receipt.StorageType != "s3-object-lock" {
		errs = append(errs, fmt.Sprintf("unsupported storage receipt type %q", receipt.StorageType))
	}
	if receipt.SubjectRoot != seal.MerkleRoot {
		errs = append(errs, "storage receipt subject root mismatch")
	}
	if !strings.EqualFold(receipt.RetentionMode, "COMPLIANCE") {
		errs = append(errs, "customer storage receipt requires COMPLIANCE Object Lock")
	}
	if !receipt.RetainUntil.After(now) {
		errs = append(errs, "storage retention is not active")
	}
	if receipt.Bucket == "" || receipt.Key == "" || receipt.VersionID == "" {
		errs = append(errs, "storage receipt missing bucket, key, or version_id")
	}
	if !validSHA256ReceiptHash(receipt.ObjectHash) {
		errs = append(errs, "storage receipt object_hash must be sha256:<hex>")
	} else if strings.TrimSpace(objectPath) != "" {
		actual, err := HashFile(objectPath)
		if err != nil {
			errs = append(errs, fmt.Sprintf("hash storage object: %v", err))
		} else if !strings.EqualFold(receipt.ObjectHash, actual) {
			errs = append(errs, fmt.Sprintf("storage receipt object_hash mismatch: receipt=%s current=%s", receipt.ObjectHash, actual))
		}
	}
	if seal.Storage.Bucket != "" && receipt.Bucket != seal.Storage.Bucket {
		errs = append(errs, "storage receipt bucket does not match seal storage metadata")
	}
	if len(errs) > 0 {
		return "invalid", path, errs
	}
	return "immutable-off-host", path, nil
}

func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func sha256HashString(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSHA256ReceiptHash(value string) bool {
	hash := strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	decoded, err := hex.DecodeString(hash)
	return err == nil && len(decoded) == sha256.Size
}
