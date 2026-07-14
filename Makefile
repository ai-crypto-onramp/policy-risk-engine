.PHONY: build test run lint docker-build docker-run clean migrate-up migrate-down

DB_URL ?= postgres://postgres:postgres@localhost:5432/policy_engine?sslmode=disable
MIGRATIONS_DIR ?= migrations

build:
	go build -o bin/policy-engine ./cmd/policy-engine

test:
	go test ./cmd/... ./internal/... -race -coverprofile=coverage.out -coverpkg=./cmd/...,./internal/...

run:
	go run ./cmd/policy-engine

lint:
	go vet ./...

migrate-up:
	DB_URL="$(DB_URL)" go run ./cmd/migrate up "$(MIGRATIONS_DIR)"

migrate-down:
	DB_URL="$(DB_URL)" go run ./cmd/migrate down "$(MIGRATIONS_DIR)"

docker-build:
	docker build -t ai-crypto-onramp/policy-risk-engine .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/policy-risk-engine

clean:
	rm -rf bin/ coverage.out