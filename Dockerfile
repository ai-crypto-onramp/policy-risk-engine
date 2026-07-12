FROM golang:1.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /policy-engine ./cmd/policy-engine

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /policy-engine /policy-engine
COPY policies /policies
ENV POLICIES_DIR=/policies
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/policy-engine"]