package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/evaluate"
	policypb "github.com/ai-crypto-onramp/policy-risk-engine/proto/policy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// grpcServer adapts the evaluate.Service to the gRPC PolicyServer interface.
type grpcServer struct {
	policypb.UnimplementedPolicyServer
	s *Services
}

// Evaluate maps the gRPC EvaluateRequest to the internal evaluate.Request,
// invokes the evaluate path, and maps the response back to the gRPC
// EvaluateResponse. The decision logic is identical to the REST path so both
// transports return the same decision for identical inputs.
func (g *grpcServer) Evaluate(ctx context.Context, req *policypb.EvaluateRequest) (*policypb.EvaluateResponse, error) {
	if g.s == nil || g.s.Evaluate == nil {
		return nil, errors.New("evaluate service not configured")
	}
	resp, err := g.s.Evaluate.Evaluate(ctx, evaluateRequestFromProto(req))
	if err != nil {
		return nil, err
	}
	return evaluateResponseToProto(resp), nil
}

func evaluateRequestFromProto(req *policypb.EvaluateRequest) evaluate.Request {
	return evaluate.Request{
		UserID:      req.GetUserId(),
		Amount:      req.GetAmount(),
		Currency:    req.GetCurrency(),
		Asset:       req.GetAsset(),
		Rail:        req.GetRail(),
		DestAddress: req.GetDestAddress(),
		DestChain:   req.GetDestChain(),
		KYTVerdict:  req.GetKytVerdict(),
		FraudScore:  req.GetFraudScore(),
		KYCStatus:   req.GetKycStatus(),
		UserTier:    req.GetUserTier(),
		Session2FA:  req.GetSession_2FaPassed(),
		FXRateToUSD: req.GetFxRateToUsd(),
	}
}

func evaluateResponseToProto(resp evaluate.Response) *policypb.EvaluateResponse {
	rules := make([]*policypb.AppliedRule, 0, len(resp.AppliedRules))
	for _, r := range resp.AppliedRules {
		rules = append(rules, &policypb.AppliedRule{Id: r.ID, Version: r.Version})
	}
	return &policypb.EvaluateResponse{
		Decision:      resp.Decision,
		Reasons:       resp.Reasons,
		AppliedRules:  rules,
		PolicyVersion: resp.PolicyVersion,
		Score:         resp.Score,
		DecisionId:    resp.DecisionID,
	}
}

// NewGRPCServer constructs the gRPC server with optional mTLS and returns it
// bound to grpcPort. When MTLS_CA_CERT is set the server requires and verifies
// client certificates signed by that CA (service-to-service mTLS). When
// MTLS_CA_CERT is unset the server is started without TLS (for local dev).
//
// Returns (server, listener, error). On error the caller should log and
// continue without gRPC.
func NewGRPCServer(s *Services, grpcPort string) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		return nil, nil, fmt.Errorf("grpc listen: %w", err)
	}
	var opts []grpc.ServerOption
	if caCertPath := os.Getenv("MTLS_CA_CERT"); caCertPath != "" {
		tlsCfg, err := buildServerTLSConfig(caCertPath)
		if err != nil {
			_ = lis.Close()
			return nil, nil, fmt.Errorf("grpc mtls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		log.Printf("grpc: mTLS enabled (ca=%s)", caCertPath)
	}
	srv := grpc.NewServer(opts...)
	policypb.RegisterPolicyServer(srv, &grpcServer{s: s})
	return srv, lis, nil
}

// buildServerTLSConfig loads the CA cert and returns a TLS config requiring
// client cert verification (mTLS). The server presents no server certificate
// by default — callers must set SERVER_TLS_CERT / SERVER_TLS_KEY to enable
// full mutual TLS. For the internal mesh this is typically handled by the
// sidecar; this config enforces client identity only.
func buildServerTLSConfig(caCertPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse ca cert")
	}
	cfg := &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	if certPath := os.Getenv("SERVER_TLS_CERT"); certPath != "" {
		keyPath := os.Getenv("SERVER_TLS_KEY")
		if keyPath == "" {
			return nil, errors.New("SERVER_TLS_CERT set but SERVER_TLS_KEY missing")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load server keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}