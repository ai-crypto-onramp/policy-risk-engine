// Command migrate is a thin wrapper around internal/db.MigrateUp/MigrateDown
// so `make migrate-up` / `make migrate-down` work without an external binary.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/db"
)

func main() {
	if err := run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// run parses args and executes the requested migration direction. It returns
// an error instead of calling os.Exit so it is testable.
func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: migrate <up|down> [migrations-dir]")
	}
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		return db.ErrMissingDBURL
	}
	dir := "migrations"
	if len(args) >= 3 {
		dir = args[2]
	}

	switch args[1] {
	case "up":
		if err := db.MigrateUp(dsn, dir); err != nil {
			return fmt.Errorf("migrate up: %w", err)
		}
	case "down":
		if err := db.MigrateDown(dsn, dir); err != nil {
			return fmt.Errorf("migrate down: %w", err)
		}
	default:
		return fmt.Errorf("unknown direction %q", args[1])
	}
	fmt.Println("migration", args[1], "complete")
	return nil
}