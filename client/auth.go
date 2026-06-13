package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// idpHTTPClient is the shared client used to talk to the IDP (token proxy and
// JWKS fetch).
var idpHTTPClient = &http.Client{Timeout: 10 * time.Second}

// clockSkewLeeway tolerates small clock differences between this service and
// the IDP when checking exp/nbf.
const clockSkewLeeway = 60 * time.Second

// idpVerifier validates RS256 JWTs issued by the IDP against its JWKS, and
// optionally enforces the issuer and audience claims.
type idpVerifier struct {
	jwks     *jwksCache
	issuer   string
	audience string
}

// newIDPVerifier builds a verifier. issuer/audience may be empty to skip those
// checks.
func newIDPVerifier(jwksURL, issuer, audience string) *idpVerifier {
	return &idpVerifier{
		jwks:     newJWKSCache(jwksURL),
		issuer:   issuer,
		audience: audience,
	}
}

// verify checks the token's signature and standard claims. It returns nil when
// the token is valid.
func (v *idpVerifier) verify(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("malformed token")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("malformed token header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("malformed token header")
	}
	// Pin the algorithm to RS256 to avoid "alg":"none" and HMAC confusion attacks.
	if header.Alg != "RS256" {
		return fmt.Errorf("unsupported token algorithm %q", header.Alg)
	}

	key, err := v.jwks.key(header.Kid)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("malformed token signature")
	}
	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sig); err != nil {
		return fmt.Errorf("invalid token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("malformed token claims")
	}
	var claims struct {
		Iss string   `json:"iss"`
		Exp int64    `json:"exp"`
		Nbf int64    `json:"nbf"`
		Aud audience `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("malformed token claims")
	}

	now := time.Now()
	if claims.Exp != 0 && now.Add(-clockSkewLeeway).After(time.Unix(claims.Exp, 0)) {
		return fmt.Errorf("token expired")
	}
	if claims.Nbf != 0 && now.Add(clockSkewLeeway).Before(time.Unix(claims.Nbf, 0)) {
		return fmt.Errorf("token not yet valid")
	}
	if v.issuer != "" && claims.Iss != v.issuer {
		return fmt.Errorf("invalid token issuer")
	}
	if v.audience != "" && !claims.Aud.contains(v.audience) {
		return fmt.Errorf("invalid token audience")
	}
	return nil
}

// audience decodes the JWT "aud" claim, which may be a single string or an
// array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			return err
		}
		*a = list
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		return err
	}
	*a = []string{single}
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// jwksCache fetches and caches an IDP's JSON Web Key Set, refreshing on a TTL
// and on cache misses (to pick up key rotation).
type jwksCache struct {
	url string
	ttl time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{
		url:  url,
		ttl:  15 * time.Minute,
		keys: map[string]*rsa.PublicKey{},
	}
}

// key returns the RSA public key for the given kid, refreshing the cache when
// the entry is missing or stale.
func (c *jwksCache) key(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	cached, ok := c.keys[kid]
	fresh := time.Since(c.fetchedAt) < c.ttl
	c.mu.RUnlock()
	if ok && fresh {
		return cached, nil
	}

	if err := c.refresh(); err != nil {
		if ok {
			// Serve the stale-but-known key if the IDP is briefly unreachable.
			return cached, nil
		}
		return nil, err
	}

	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no JWKS key matches token kid %q", kid)
	}
	return key, nil
}

func (c *jwksCache) refresh() error {
	resp, err := idpHTTPClient.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// rsaPublicKeyFromJWK builds an RSA public key from the base64url-encoded
// modulus (n) and exponent (e) of a JWK.
func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if e.BitLen() > 31 {
		return nil, fmt.Errorf("exponent too large")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}
