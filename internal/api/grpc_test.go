package api

import (
	"context"
	"net"
	"testing"
	"time"

	policypb "github.com/ai-crypto-onramp/policy-risk-engine/proto/policy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestGRPCEvaluateDenyNotWhitelisted(t *testing.T) {
	s := newTestServices(t)
	srv, lis, err := NewGRPCServer(s, "0")
	if err != nil {
		t.Fatalf("new grpc: %v", err)
	}
	defer srv.Stop()
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := policypb.NewPolicyClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Evaluate(ctx, &policypb.EvaluateRequest{
		UserId: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KytVerdict: "clean", FraudScore: 0.1, KycStatus: "verified",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s", resp.Decision)
	}
	if resp.DecisionId == "" {
		t.Error("empty decision id")
	}
}

func TestGRPCEvaluateMatchesREST(t *testing.T) {
	s := newTestServices(t)
	_, _ = s.Whitelist.Add(context.Background(), "usr_1", "ethereum", "0xabc", "")
	_, _ = s.Whitelist.Verify(context.Background(), "usr_1", "ethereum", "0xabc")

	grpcReq := &policypb.EvaluateRequest{
		UserId: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KytVerdict: "clean", FraudScore: 0.1, KycStatus: "verified",
	}

	srv, lis, err := NewGRPCServer(s, "0")
	if err != nil {
		t.Fatalf("new grpc: %v", err)
	}
	defer srv.Stop()
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := policypb.NewPolicyClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	grpcResp, err := client.Evaluate(ctx, grpcReq)
	if err != nil {
		t.Fatalf("grpc evaluate: %v", err)
	}

	restResp, err := s.Evaluate.Evaluate(ctx, evaluateRequestFromProto(grpcReq))
	if err != nil {
		t.Fatalf("rest evaluate: %v", err)
	}
	if grpcResp.Decision != restResp.Decision {
		t.Fatalf("decision mismatch: grpc=%s rest=%s", grpcResp.Decision, restResp.Decision)
	}
	if grpcResp.PolicyVersion != restResp.PolicyVersion {
		t.Fatalf("version mismatch: grpc=%s rest=%s", grpcResp.PolicyVersion, restResp.PolicyVersion)
	}
	if grpcResp.Score != restResp.Score {
		t.Fatalf("score mismatch: grpc=%v rest=%v", grpcResp.Score, restResp.Score)
	}
}

func TestNewGRPCServerBadPort(t *testing.T) {
	s := newTestServices(t)
	if _, _, err := NewGRPCServer(s, "not-a-port"); err == nil {
		t.Fatal("expected error for bad port")
	}
}

func TestGRPCServerListenAddr(t *testing.T) {
	s := newTestServices(t)
	srv, lis, err := NewGRPCServer(s, "0")
	if err != nil {
		t.Fatalf("new grpc: %v", err)
	}
	defer srv.Stop()
	_ = lis.Close()
	if lis.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("expected non-zero port after listen")
	}
}