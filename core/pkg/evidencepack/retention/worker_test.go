package retention

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestDefaultPolicyNewWorkerAndRunOnce(t *testing.T) {
	policy := DefaultPolicy()
	if policy.MaxAge != 90*24*time.Hour || policy.ArchiveAge != 30*24*time.Hour || policy.DeleteAge != 365*24*time.Hour {
		t.Fatalf("DefaultPolicy() = %#v", policy)
	}
	if policy.MinRetainCount != 1000 {
		t.Fatalf("MinRetainCount = %d", policy.MinRetainCount)
	}

	store := &fakeObjectStore{
		listFn: func(_ context.Context, prefix string) ([]string, error) {
			if prefix != "" {
				t.Fatalf("List prefix = %q, want empty", prefix)
			}
			return []string{"hash-1", "hash-2"}, nil
		},
	}
	worker := NewWorker(store, policy, testLogger())
	if worker.store != store || worker.policy != policy || worker.stopCh == nil {
		t.Fatalf("NewWorker() = %#v", worker)
	}
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}

	wantErr := errors.New("list failed")
	worker = NewWorker(&fakeObjectStore{
		listFn: func(context.Context, string) ([]string, error) {
			return nil, wantErr
		},
	}, policy, testLogger())
	if err := worker.RunOnce(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("RunOnce() error = %v, want %v", err, wantErr)
	}
}

func TestStartStopContextAndTickerPaths(t *testing.T) {
	t.Run("stop without ticker", func(t *testing.T) {
		worker := NewWorker(&fakeObjectStore{}, DefaultPolicy(), testLogger())
		worker.Stop()
	})

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		worker := NewWorker(&fakeObjectStore{}, DefaultPolicy(), testLogger())
		worker.Start(ctx, time.Hour)
		time.Sleep(10 * time.Millisecond)
		worker.Stop()
	})

	t.Run("stop signal", func(t *testing.T) {
		worker := NewWorker(&fakeObjectStore{}, DefaultPolicy(), testLogger())
		worker.Start(context.Background(), time.Hour)
		worker.Stop()
		time.Sleep(10 * time.Millisecond)
	})

	t.Run("ticker logs run error", func(t *testing.T) {
		called := make(chan struct{})
		var once sync.Once
		worker := NewWorker(&fakeObjectStore{
			listFn: func(context.Context, string) ([]string, error) {
				once.Do(func() { close(called) })
				return nil, errors.New("cycle failed")
			},
		}, DefaultPolicy(), testLogger())

		worker.Start(context.Background(), time.Nanosecond)
		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for retention tick")
		}
		worker.Stop()
	})
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeObjectStore struct {
	listFn func(context.Context, string) ([]string, error)
}

func (s *fakeObjectStore) Put(context.Context, string, io.Reader) error {
	return nil
}

func (s *fakeObjectStore) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, nil
}

func (s *fakeObjectStore) Exists(context.Context, string) (bool, error) {
	return false, nil
}

func (s *fakeObjectStore) Delete(context.Context, string) error {
	return nil
}

func (s *fakeObjectStore) List(ctx context.Context, prefix string) ([]string, error) {
	if s.listFn == nil {
		return nil, nil
	}
	return s.listFn(ctx, prefix)
}
