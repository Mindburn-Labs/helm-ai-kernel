package database

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Region represents a database region.
type Region string

const (
	RegionPrimary   Region = "primary"
	RegionSecondary Region = "secondary"
	RegionTertiary  Region = "tertiary"
)

// MultiRegionConfig holds configuration for multi-region database routing.
type MultiRegionConfig struct {
	Primary   ConnectionConfig
	Secondary *ConnectionConfig // Optional
	Tertiary  *ConnectionConfig // Optional

	HealthCheckInterval time.Duration
	FailoverTimeout     time.Duration
	ReadPreference      ReadPreference
}

// ConnectionConfig holds configuration for a single database connection.
type ConnectionConfig struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
	SSLMode  string
	Region   Region
}

// ReadPreference determines how reads are routed.
type ReadPreference int

const (
	// ReadPrimary routes all reads to primary (strong consistency).
	ReadPrimary ReadPreference = iota
	// ReadSecondaryPreferred routes reads to secondary when available.
	ReadSecondaryPreferred
	// ReadNearest routes reads to the nearest healthy region.
	ReadNearest
)

// MultiRegionRouter routes database connections across multiple regions.
type MultiRegionRouter struct {
	mu          sync.RWMutex
	config      MultiRegionConfig
	connections map[Region]*sql.DB
	health      map[Region]bool
	stopCh      chan struct{}
}

// NewMultiRegionRouter creates a new multi-region database router.
func NewMultiRegionRouter(cfg MultiRegionConfig) (*MultiRegionRouter, error) {
	router := &MultiRegionRouter{
		config:      cfg,
		connections: make(map[Region]*sql.DB),
		health:      make(map[Region]bool),
		stopCh:      make(chan struct{}),
	}

	// Connect to primary (required)
	primaryDB, err := connectDB(cfg.Primary)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to primary: %w", err)
	}
	router.connections[RegionPrimary] = primaryDB
	router.health[RegionPrimary] = true

	// Connect to secondary (optional)
	if cfg.Secondary != nil {
		secondaryDB, err := connectDB(*cfg.Secondary)
		if err != nil {
			// Log warning but don't fail
			router.health[RegionSecondary] = false
		} else {
			router.connections[RegionSecondary] = secondaryDB
			router.health[RegionSecondary] = true
		}
	}

	// Connect to tertiary (optional)
	if cfg.Tertiary != nil {
		tertiaryDB, err := connectDB(*cfg.Tertiary)
		if err != nil {
			router.health[RegionTertiary] = false
		} else {
			router.connections[RegionTertiary] = tertiaryDB
			router.health[RegionTertiary] = true
		}
	}

	return router, nil
}

func connectDB(cfg ConnectionConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode,
	)
	return sql.Open("postgres", dsn)
}

// HealthStatus returns the health status of all regions.
func (r *MultiRegionRouter) HealthStatus() map[Region]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status := make(map[Region]bool)
	for k, v := range r.health {
		status[k] = v
	}
	return status
}

// Close closes all database connections.
func (r *MultiRegionRouter) Close() error {
	close(r.stopCh)

	var errs []error
	for _, db := range r.connections {
		if db != nil {
			if err := db.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}
	return nil
}
