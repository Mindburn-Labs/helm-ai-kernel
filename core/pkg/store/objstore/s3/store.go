//go:build s3

// Package s3 implements the ObjectStore interface using S3-compatible storage.
// This works with MinIO (local/prod) and any S3-compatible service.
package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/objstore"
)

// Config holds S3 connection parameters.
type Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
	Region    string
}

// Store implements ObjectStore using S3-compatible storage.
type Store struct {
	client *minio.Client
	bucket string
}

// New creates a new S3-backed object store.
func New(cfg Config) (*Store, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}

	return &Store{
		client: client,
		bucket: cfg.Bucket,
	}, nil
}

// EnsureBucket creates the bucket if it doesn't exist.
func (s *Store) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("check bucket existence: %w", err)
	}
	if !exists {
		if err := s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("create bucket: %w", err)
		}
	}
	return nil
}

func (s *Store) objectKey(hash string) string {
	clean := strings.TrimPrefix(hash, "sha256:")
	if len(clean) < 4 {
		return clean
	}
	// Use sharded key layout for performance
	return clean[:2] + "/" + clean[2:4] + "/" + clean
}

func (s *Store) Put(ctx context.Context, hash string, data io.Reader) error {
	key := s.objectKey(hash)

	// Read all data to get size (S3 needs content length for PutObject)
	buf, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	_, err = s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(buf), int64(len(buf)),
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
		})
	if err != nil {
		return fmt.Errorf("put object %s: %w", key, err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, hash string) (io.ReadCloser, error) {
	key := s.objectKey(hash)
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get object %s: %w", key, err)
	}

	// Check if object exists by reading stat
	if _, err := obj.Stat(); err != nil {
		errResp := minio.ToErrorResponse(err)
		if errResp.Code == "NoSuchKey" {
			_ = obj.Close()
			return nil, &objstore.ErrNotFound{Hash: hash}
		}
		_ = obj.Close()
		return nil, fmt.Errorf("stat object %s: %w", key, err)
	}

	return obj, nil
}

func (s *Store) Exists(ctx context.Context, hash string) (bool, error) {
	key := s.objectKey(hash)
	_, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		errResp := minio.ToErrorResponse(err)
		if errResp.Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("stat object %s: %w", key, err)
	}
	return true, nil
}

func (s *Store) Delete(ctx context.Context, hash string) error {
	key := s.objectKey(hash)
	err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("delete object %s: %w", key, err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, prefix string) ([]string, error) {
	var hashes []string
	opts := minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}

	for obj := range s.client.ListObjects(ctx, s.bucket, opts) {
		if obj.Err != nil {
			return nil, fmt.Errorf("list objects: %w", obj.Err)
		}
		// Extract hash from sharded key
		parts := strings.Split(obj.Key, "/")
		hash := parts[len(parts)-1]
		hashes = append(hashes, hash)
	}
	return hashes, nil
}
