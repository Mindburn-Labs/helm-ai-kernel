package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Store implements Store interface using AWS S3.
// Artifacts are stored with their SHA-256 hash as the key prefix.
type S3Store struct {
	client *s3.Client
	bucket string
	prefix string // Optional key prefix (e.g., "artifacts/")
}

// S3StoreConfig holds configuration for S3Store.
type S3StoreConfig struct {
	Bucket   string
	Region   string
	Endpoint string // Optional custom endpoint (for MinIO, LocalStack, etc.)
	Prefix   string // Optional key prefix
}

// NewS3Store creates a new S3-backed artifact store.
func NewS3Store(ctx context.Context, cfg S3StoreConfig) (*S3Store, error) {
	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with optional custom endpoint
	clientOpts := func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true // Required for MinIO/LocalStack
		}
	}

	client := s3.NewFromConfig(awsCfg, clientOpts)

	return &S3Store{
		client: client,
		bucket: cfg.Bucket,
		prefix: cfg.Prefix,
	}, nil
}

// Store persists data to S3 and returns its content hash.
func (s *S3Store) Store(ctx context.Context, data []byte) (string, error) {
	// 1. Compute Hash
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return "", fmt.Errorf("hash computation failed: %w", err)
	}
	hashBytes := h.Sum(nil)
	hashStr := hex.EncodeToString(hashBytes)
	prefixedHash := "sha256:" + hashStr

	// 2. Determine S3 key
	key := s.prefix + hashStr + ".blob"

	// 3. Check if object already exists (idempotent)
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		// Already exists
		return prefixedHash, nil
	}

	// 4. Upload object
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return "", fmt.Errorf("s3 put failed: %w", err)
	}

	return prefixedHash, nil
}

// Get retrieves data from S3 by its content hash.
func (s *S3Store) Get(ctx context.Context, hash string) ([]byte, error) {
	// Parse "sha256:..."
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	key := s.prefix + rawHash + ".blob"

	// Download object
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get failed for %s: %w", hash, err)
	}
	defer func() { _ = result.Body.Close() }()

	return io.ReadAll(result.Body)
}

// Exists checks if an artifact exists in S3.
func (s *S3Store) Exists(ctx context.Context, hash string) (bool, error) {
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return false, fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	key := s.prefix + rawHash + ".blob"

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// Check if it's a "not found" error
		return false, nil
	}

	return true, nil
}

// Delete removes an artifact from S3.
func (s *S3Store) Delete(ctx context.Context, hash string) error {
	if len(hash) < 7 || hash[:7] != "sha256:" {
		return fmt.Errorf("invalid hash format: %s", hash)
	}
	rawHash := hash[7:]

	key := s.prefix + rawHash + ".blob"

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3 delete failed for %s: %w", hash, err)
	}

	return nil
}
