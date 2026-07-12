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
	if len(os.Args) < 2 {
		log.Fatal("usage: migrate <up|down> [migrations-dir]")
	}
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		log.Fatal(db.ErrMissingDBURL)
	}
	dir := "migrations"
	if len(os.Args) >= 3 {
		dir = os.Args[2]
	}

	var err error
	switch os.Args[1] {
	case "up":
		err = db.MigrateUp(dsn, dir)
	case "down":
		err = db.MigrateDown(dsn, dir)
	default:
		log.Fatalf("unknown direction %q", os.Args[1])
	}
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println("migration", os.Args[1], "complete")
}