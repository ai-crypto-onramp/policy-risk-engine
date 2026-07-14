.PHONY: build test run lint cover docker-build docker-run clean migrate-up migrate-down

build:
	go build -o bin/policy-engine ./cmd/policy-engine

test:
	go test ./internal/... -race -coverprofile=coverage.out -coverpkg=./internal/...

run:
	go run ./cmd/policy-engine

lint:
	golangci-lint run

cover: test
	go tool cover -func=coverage.out | tail -1

migrate-up:
	go run ./cmd/migrate --up

migrate-down:
	go run ./cmd/migrate --down

docker-build:
	docker build -t ai-crypto-onramp/policy-risk-engine .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/policy-risk-engine

clean:
	rm -rf bin/ coverage.out