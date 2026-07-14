FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /policy-engine ./cmd/policy-engine && \
    CGO_ENABLED=0 GOOS=linux go build -o /migrate ./cmd/migrate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /policy-engine /policy-engine
COPY --from=builder /migrate /migrate
COPY policies /policies
COPY migrations /migrations
ENV POLICIES_DIR=/policies
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/policy-engine"]