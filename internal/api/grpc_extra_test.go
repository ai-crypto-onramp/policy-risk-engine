package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	policypb "github.com/ai-crypto-onramp/policy-risk-engine/proto/policy/v1"
)

// writeTestCACert generates a self-signed CA certificate and writes it to a
// temp file, returning the path. Used to exercise buildServerTLSConfig's
// success paths.
func writeTestCACert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestBuildServerTLSConfigMissingFile(t *testing.T) {
	if _, err := buildServerTLSConfig("/nonexistent/cert.pem"); err == nil {
		t.Fatal("expected error for missing ca cert file")
	}
}

func TestBuildServerTLSConfigBadPEM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildServerTLSConfig(p); err == nil {
		t.Fatal("expected error for unparseable pem")
	}
}

func TestBuildServerTLSConfigCertWithoutKey(t *testing.T) {
	caPath := writeTestCACert(t)
	t.Setenv("SERVER_TLS_CERT", "/some/cert.pem")
	t.Setenv("SERVER_TLS_KEY", "")
	if _, err := buildServerTLSConfig(caPath); err == nil {
		t.Fatal("expected error when SERVER_TLS_CERT set but SERVER_TLS_KEY empty")
	}
}

func TestBuildServerTLSConfigKeyMissingEnv(t *testing.T) {
	caPath := writeTestCACert(t)
	t.Setenv("SERVER_TLS_CERT", "/some/cert.pem")
	t.Setenv("SERVER_TLS_KEY", "")
	if _, err := buildServerTLSConfig(caPath); err == nil {
		t.Fatal("expected error when key env missing")
	}
}

func TestBuildServerTLSConfigCertBadPath(t *testing.T) {
	caPath := writeTestCACert(t)
	t.Setenv("SERVER_TLS_CERT", "/definitely/not/here.pem")
	t.Setenv("SERVER_TLS_KEY", "/also/not/here.pem")
	if _, err := buildServerTLSConfig(caPath); err == nil {
		t.Fatal("expected error when cert file missing")
	}
}

func TestBuildServerTLSConfigSuccessNoServerCert(t *testing.T) {
	caPath := writeTestCACert(t)
	cfg, err := buildServerTLSConfig(caPath)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil config")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("expected no server certificates when env unset")
	}
}

func TestGRPCEvaluateNilServices(t *testing.T) {
	g := &grpcServer{}
	if _, err := g.Evaluate(context.Background(), &policypb.EvaluateRequest{}); err == nil {
		t.Fatal("expected error when services nil")
	}
}

func TestGRPCEvaluateNilEvaluateService(t *testing.T) {
	g := &grpcServer{s: &Services{}}
	if _, err := g.Evaluate(context.Background(), &policypb.EvaluateRequest{}); err == nil {
		t.Fatal("expected error when Evaluate service nil")
	}
}