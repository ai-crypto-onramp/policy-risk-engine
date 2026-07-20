package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	policypb "github.com/ai-crypto-onramp/policy-risk-engine/proto/policy/v1"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/evaluate"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
)

func TestAppErrorMessage(t *testing.T) {
	ae := newAppError("code", "msg", 400)
	if ae.Error() != "msg" {
		t.Errorf("Error(): %q", ae.Error())
	}
}

func TestToAppErrorReviewAlreadyResolved(t *testing.T) {
	s := newTestServices(t)
	_, _ = s.Review.Park(context.Background(), "dec_1", "")
	_, _ = s.Review.Resolve(context.Background(), "dec_1", "r", review.ResolutionAllow)
	body := bytes.NewBufferString(`{"assignee":"r","resolution":"ALLOW"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/review/dec_1/resolve", body)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestListWhitelistHandlerMissingUserID(t *testing.T) {
	s := newTestServices(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/whitelist/", nil)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	// net/http serves the pattern with the trailing slash; path value empty.
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestListReviewHandlerStoreError(t *testing.T) {
	s := newTestServices(t)
	s.Review = review.NewService(errReviewStore{})
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/review", nil)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestListWhitelistHandlerStoreError(t *testing.T) {
	s := newTestServices(t)
	s.Whitelist = whitelist.NewService(errWLStore{})
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/whitelist/usr_1", nil)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestListRulesHandlerNilEngine(t *testing.T) {
	s := newTestServices(t)
	s.Engine = nil
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/rules", nil)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"rules":[]`) {
		t.Errorf("expected empty rules array: %s", rec.Body.String())
	}
}

func TestGetRuleHandlerNilEngine(t *testing.T) {
	s := newTestServices(t)
	s.Engine = nil
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/rules/v1", nil)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: %d", rec.Code)
	}
}

func TestEvaluateHandlerAuthEnabled(t *testing.T) {
	s := newTestServices(t)
	s.Auth = &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	token := makeJWT(t, Claims{Sub: "usr_1", Iss: "test-issuer", Scope: "policy:admin"})
	body := bytes.NewBufferString(`{"user_id":"usr_1","amount":"100","currency":"USD","dest_address":"0xabc","dest_chain":"ethereum","kyt_verdict":"clean","fraud_score":0.1,"kyc_status":"verified"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/evaluate", body)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestEvaluateHandlerAuthEnabledInvalidToken(t *testing.T) {
	s := newTestServices(t)
	s.Auth = &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	body := bytes.NewBufferString(`{"user_id":"usr_1"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/evaluate", body)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: %d", rec.Code)
	}
}

func TestEvaluateHandlerEvaluateError(t *testing.T) {
	s := newTestServices(t)
	// A request that passes JSON decoding but fails evaluate.validate()
	// returns a plain error, which toAppError maps to internal_error (500).
	body := bytes.NewBufferString(`{"user_id":"usr_1","currency":"USD","dest_address":"0x1","dest_chain":"eth"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/evaluate", body)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestDecodeJSONReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", errReader{})
	if err := decodeJSON(req, &struct{}{}); err == nil {
		t.Fatal("expected error from read failure")
	}
}

func TestDecodeJSONInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(`{"bad`))
	if err := decodeJSON(req, &struct{}{}); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestAudienceContainsJSONNumber(t *testing.T) {
	// fmt.Sprint(json.Number("123")) returns "123" — the audienceContains
	// []any branch stringifies each element.
	if !audienceContains([]any{json.Number("123")}, "123") {
		t.Error("json.Number should match its string form")
	}
}

func TestAudienceContainsOtherType(t *testing.T) {
	if audienceContains(42, "42") {
		t.Error("int aud should not match")
	}
}

func TestEvaluateRequestFromProtoRoundtrip(t *testing.T) {
	req := &policypb.EvaluateRequest{
		UserId: "u", Amount: "1", Currency: "USD", Asset: "USDC",
		Rail: "ach", DestAddress: "0x1", DestChain: "eth", KytVerdict: "clean",
		FraudScore: 0.2, KycStatus: "verified", UserTier: "tier_1",
		Session_2FaPassed: true, FxRateToUsd: 1.1,
	}
	got := evaluateRequestFromProto(req)
	if got.UserID != "u" || got.Amount != "1" || got.Currency != "USD" {
		t.Errorf("got: %+v", got)
	}
	if got.Asset != "USDC" || got.Rail != "ach" || got.DestAddress != "0x1" {
		t.Errorf("asset/rail/dest: %+v", got)
	}
	if got.DestChain != "eth" || got.KYTVerdict != "clean" {
		t.Errorf("chain/kyt: %+v", got)
	}
	if got.FraudScore != 0.2 || got.KYCStatus != "verified" {
		t.Errorf("fraud/kyc: %+v", got)
	}
	if got.UserTier != "tier_1" || !got.Session2FA || got.FXRateToUSD != 1.1 {
		t.Errorf("tier/2fa/fx: %+v", got)
	}
}

func TestEvaluateResponseToProtoWithRules(t *testing.T) {
	resp := evaluate.Response{
		Decision:      "manual_review",
		Reasons:       []string{"r"},
		AppliedRules:  []evaluate.AppliedRule{{ID: "r1", Version: "v1"}, {ID: "r2", Version: "v2"}},
		PolicyVersion: "v1",
		Score:         0.5,
		DecisionID:    "dec_1",
	}
	out := evaluateResponseToProto(resp)
	if out.Decision != "manual_review" {
		t.Errorf("decision: %s", out.Decision)
	}
	if len(out.AppliedRules) != 2 {
		t.Fatalf("applied rules: %d", len(out.AppliedRules))
	}
	if out.AppliedRules[0].Id != "r1" || out.AppliedRules[1].Version != "v2" {
		t.Errorf("rules: %+v", out.AppliedRules)
	}
	if out.PolicyVersion != "v1" || out.Score != 0.5 || out.DecisionId != "dec_1" {
		t.Errorf("meta: %+v", out)
	}
}

// errReader returns an error on Read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

type errReviewStore struct{}

func (errReviewStore) Put(review.Item) error                { return nil }
func (errReviewStore) Get(string) (review.Item, bool, error) { return review.Item{}, false, nil }
func (errReviewStore) List(string) ([]review.Item, error)    { return nil, errors.New("list boom") }
func (errReviewStore) Update(review.Item) error              { return nil }

type errWLStore struct{}

func (errWLStore) Add(whitelist.Entry) error                                          { return nil }
func (errWLStore) List(string) ([]whitelist.Entry, error)                             { return nil, errors.New("list boom") }
func (errWLStore) Get(string, string, string) (whitelist.Entry, bool, error) {
	return whitelist.Entry{}, false, nil
}
func (errWLStore) Update(whitelist.Entry) error { return nil }