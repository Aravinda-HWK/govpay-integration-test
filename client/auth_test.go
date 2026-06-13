package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testKid = "test-key-1"

// signTestJWT builds an RS256 JWT signed with key, using the given alg in the
// header (so tests can forge "none"/"HS256") and the given claims.
func signTestJWT(t *testing.T, key *rsa.PrivateKey, alg, kid string, claims map[string]interface{}) string {
	t.Helper()
	enc := func(v interface{}) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	payload := enc(claims)
	signingInput := header + "." + payload

	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer stands up an httptest server exposing key's public half as a JWKS.
func jwksServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	pub := key.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	body := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, kid, n, e)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func newTestVerifier(t *testing.T) (*idpVerifier, *rsa.PrivateKey, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, key, testKid)
	v := newIDPVerifier(srv.URL, "https://idp.example/oauth2/token", "client-123")
	return v, key, srv.Close
}

func TestVerifyValidToken(t *testing.T) {
	v, key, cleanup := newTestVerifier(t)
	defer cleanup()

	token := signTestJWT(t, key, "RS256", testKid, map[string]interface{}{
		"iss": "https://idp.example/oauth2/token",
		"aud": "client-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err := v.verify(token); err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
}

func TestVerifyAudienceArray(t *testing.T) {
	v, key, cleanup := newTestVerifier(t)
	defer cleanup()

	token := signTestJWT(t, key, "RS256", testKid, map[string]interface{}{
		"iss": "https://idp.example/oauth2/token",
		"aud": []string{"other", "client-123"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err := v.verify(token); err != nil {
		t.Fatalf("expected valid token with aud array, got: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	v, key, cleanup := newTestVerifier(t)
	defer cleanup()

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"iss": "https://idp.example/oauth2/token",
			"aud": "client-123",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	cases := []struct {
		name  string
		token string
	}{
		{"expired", signTestJWT(t, key, "RS256", testKid, map[string]interface{}{
			"iss": "https://idp.example/oauth2/token", "aud": "client-123",
			"exp": time.Now().Add(-2 * time.Hour).Unix(),
		})},
		{"wrong issuer", signTestJWT(t, key, "RS256", testKid, map[string]interface{}{
			"iss": "https://evil.example", "aud": "client-123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})},
		{"wrong audience", signTestJWT(t, key, "RS256", testKid, map[string]interface{}{
			"iss": "https://idp.example/oauth2/token", "aud": "someone-else",
			"exp": time.Now().Add(time.Hour).Unix(),
		})},
		{"signed by unknown key", signTestJWT(t, otherKey, "RS256", testKid, base())},
		{"alg none", signTestJWT(t, key, "none", testKid, base())},
		{"alg HS256 (confusion)", signTestJWT(t, key, "HS256", testKid, base())},
		{"unknown kid", signTestJWT(t, key, "RS256", "missing-kid", base())},
		{"malformed", "not.a.jwt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.verify(tc.token); err == nil {
				t.Fatalf("expected %s to be rejected, but it passed", tc.name)
			}
		})
	}
}

func TestValidateRefNoOnly(t *testing.T) {
	cases := []struct {
		name    string
		params  []Param
		wantErr bool
	}{
		{"valid", []Param{{ParamName: "refNo", Value: "ABC123456"}}, false},
		{"empty value", []Param{{ParamName: "refNo", Value: ""}}, true},
		{"non-alphanumeric", []Param{{ParamName: "refNo", Value: "ABC-123"}}, true},
		{"wrong name", []Param{{ParamName: "tin", Value: "123"}}, true},
		{"too long", []Param{{ParamName: "refNo", Value: "ABCDEFGHIJKLMNOPQRSTU"}}, true}, // 21 chars
		{"extra param", []Param{{ParamName: "refNo", Value: "AB"}, {ParamName: "tin", Value: "1"}}, true},
		{"non-string", []Param{{ParamName: "refNo", Value: 123}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateRefNoOnly(tc.params)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}
