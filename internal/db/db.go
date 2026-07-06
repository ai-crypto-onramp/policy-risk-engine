package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

const (
	defaultConnectTimeout = 10 * time.Second
	defaultPingInterval    = 1 * time.Second
)

// Connect opens the database at dsn, pings it until it is reachable, and returns
// the live *sql.DB. A nil/empty dsn returns ErrMissingDBURL.
func Connect(ctx context.Context, dsn string) (*sql.DB, error) {
	if dsn == "" {
		return nil, ErrMissingDBURL
	}
	// lib/pq needs ?sslmode if absent; don't override an explicit one.
	if u, err := url.Parse(dsn); err == nil && u.Scheme == "postgres" && u.Query().Get("sslmode") == "" {
		u.Query().Set("sslmode", "disable")
		dsn = u.String()
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	if err := waitForReady(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	log.Println("db ready")
	return db, nil
}

func waitForReady(ctx context.Context, db *sql.DB) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultConnectTimeout)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("db: connect timed out")
		}
		if err := db.PingContext(ctx); err == nil {
			return nil
		}
		time.Sleep(defaultPingInterval)
	}
}

// MigrateUp applies all migrations in migrationsDir against db (postgres dsn).
func MigrateUp(dsn, migrationsDir string) error {
	m, err := migrate.New("file://"+migrationsDir, dsn)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// MigrateDown reverses all migrations in migrationsDir against db (postgres dsn).
func MigrateDown(dsn, migrationsDir string) error {
	m, err := migrate.New("file://"+migrationsDir, dsn)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}
	defer m.Close()

	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

// ErrMissingDBURL is returned when DB_URL is not configured.
var ErrMissingDBURL = errors.New("DB_URL is required")