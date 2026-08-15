package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression probe: /verify endpoint should include decoded claims in the
// response even when the token is expired or not yet valid.
func TestProbe_VerifyExpiredTokenReturnsClaims(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	secret := []byte("test-secret")
	api := NewWithClock(secret, 0, func() time.Time { return now })
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	signBody, _ := json.Marshal(map[string]any{"claims": map[string]any{
		"sub": "alice",
		"iss": "test-issuer",
		"exp": now.Unix() - 100,
	}})
	signResp, err := http.DefaultClient.Post(srv.URL+"/sign", "application/json", bytes.NewReader(signBody))
	if err != nil {
		t.Fatal(err)
	}
	signData, _ := io.ReadAll(signResp.Body)
	signResp.Body.Close()

	var signOut struct{ Token string }
	json.Unmarshal(signData, &signOut)
	if signOut.Token == "" {
		t.Fatal("failed to sign token")
	}

	verifyBody, _ := json.Marshal(map[string]any{"token": signOut.Token})
	verifyResp, err := http.DefaultClient.Post(srv.URL+"/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatal(err)
	}
	verifyData, _ := io.ReadAll(verifyResp.Body)
	verifyResp.Body.Close()

	var out struct {
		Valid  bool           `json:"valid"`
		Error  string         `json:"error"`
		Claims map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(verifyData, &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid {
		t.Fatalf("expired token should not be valid")
	}
	if out.Claims == nil {
		t.Fatalf("expired token response should include claims, got nil")
	}
	if out.Claims["sub"] != "alice" {
		t.Fatalf("claims[sub] should be alice, got %v", out.Claims["sub"])
	}
}
