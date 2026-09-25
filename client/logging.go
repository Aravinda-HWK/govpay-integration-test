package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// debugLogging turns on verbose diagnostics: raw (encrypted) request/response
// bodies, decrypted request values, plaintext response values before
// encryption, and the per-transaction AES key. Enable with
// GOVPAY_LOG_LEVEL=debug. It is meant for integration testing with sample data
// only — it writes decrypted payment data to the log.
var debugLogging bool

// maxLoggedBody caps how much of a request/response body is written to the log.
const maxLoggedBody = 16 * 1024

type ctxKey int

const requestIDKey ctxKey = 0

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
}

// requestID returns the id attached to r by logRequest, or "-".
func requestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey).(string); ok {
		return id
	}
	return "-"
}

// logf logs at info level, prefixed with the request id.
func logf(r *http.Request, format string, args ...interface{}) {
	log.Printf("[%s] "+format, append([]interface{}{requestID(r)}, args...)...)
}

// debugf logs only when debug logging is enabled.
func debugf(r *http.Request, format string, args ...interface{}) {
	if debugLogging {
		log.Printf("[%s] DEBUG "+format, append([]interface{}{requestID(r)}, args...)...)
	}
}

// fail logs the underlying cause of an error response (which the client only
// sees as a generic message) and writes the JSON error.
func fail(w http.ResponseWriter, r *http.Request, status int, code, msg string, cause error) {
	if cause != nil {
		logf(r, "ERROR %d %s: %s (cause: %v)", status, code, msg, cause)
	} else {
		logf(r, "ERROR %d %s: %s", status, code, msg)
	}
	writeJSON(w, status, ErrorResponse{Error: code, Message: msg})
}

// responseRecorder captures the status code and (a bounded copy of) the body
// written by a handler.
type responseRecorder struct {
	http.ResponseWriter
	status int
	size   int
	body   bytes.Buffer
}

func (rr *responseRecorder) WriteHeader(status int) {
	rr.status = status
	rr.ResponseWriter.WriteHeader(status)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	if rr.status == 0 {
		rr.status = http.StatusOK
	}
	if room := maxLoggedBody - rr.body.Len(); room > 0 {
		if len(b) < room {
			room = len(b)
		}
		rr.body.Write(b[:room])
	}
	n, err := rr.ResponseWriter.Write(b)
	rr.size += n
	return n, err
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = newRequestID()
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
		w.Header().Set("X-Request-ID", id)

		start := time.Now()
		logf(r, "--> %s %s remote=%s xff=%q ua=%q content-type=%q content-length=%d",
			r.Method, r.URL.RequestURI(), r.RemoteAddr, r.Header.Get("X-Forwarded-For"),
			r.UserAgent(), r.Header.Get("Content-Type"), r.ContentLength)
		logf(r, "    headers: %s", formatHeaders(r.Header))

		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				logf(r, "    could not read request body: %v", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			debugf(r, "request body (raw, %d bytes): %s", len(body), truncate(string(body)))
		}

		rec := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		logf(r, "<-- %d %s %s bytes=%d duration=%s",
			rec.status, r.Method, r.URL.Path, rec.size, time.Since(start).Round(time.Microsecond))
		// A successful token response carries the access token; never log it.
		isToken := strings.HasSuffix(r.URL.Path, "/generatetoken") && rec.status < 400
		if (debugLogging || rec.status >= 400) && !isToken {
			log.Printf("[%s]     response body: %s", id, truncate(rec.body.String()))
		}
	})
}

// formatHeaders renders request headers with credentials redacted.
func formatHeaders(h http.Header) string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		value := strings.Join(h[name], ",")
		switch strings.ToLower(name) {
		case "authorization":
			value = redactAuthorization(value)
		case "transactionkey":
			value = fmt.Sprintf("<%d chars, sha256=%s>", len(value), fingerprint([]byte(value)))
		case "cookie":
			value = "<redacted>"
		}
		parts = append(parts, fmt.Sprintf("%s=%q", name, value))
	}
	return strings.Join(parts, " ")
}

// redactAuthorization keeps the scheme and a short prefix so a token can be
// correlated without leaking it. For Basic auth the client id is shown.
func redactAuthorization(v string) string {
	scheme, cred, ok := strings.Cut(v, " ")
	if !ok {
		return fmt.Sprintf("<%d chars, no scheme>", len(v))
	}
	if strings.EqualFold(scheme, "Basic") {
		if decoded, err := base64.StdEncoding.DecodeString(cred); err == nil {
			user, _, _ := strings.Cut(string(decoded), ":")
			return fmt.Sprintf("Basic <client_id=%q, secret redacted>", user)
		}
		return "Basic <not valid base64>"
	}
	prefix := cred
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return fmt.Sprintf("%s %s…(%d chars)", scheme, prefix, len(cred))
}

// jwtSummary decodes (without verifying) the header and main claims of a JWT
// for diagnostics.
func jwtSummary(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Sprintf("not a JWT (%d segments)", len(parts))
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]interface{}
	_ = json.Unmarshal(claims, &c)
	summary := map[string]interface{}{}
	for _, k := range []string{"iss", "aud", "sub", "client_id", "scope", "exp", "nbf", "iat"} {
		if v, ok := c[k]; ok {
			summary[k] = v
		}
	}
	if exp, ok := c["exp"].(float64); ok {
		summary["exp_in"] = time.Until(time.Unix(int64(exp), 0)).Round(time.Second).String()
	}
	s, _ := json.Marshal(summary)
	return fmt.Sprintf("header=%s claims=%s", header, s)
}

func truncate(s string) string {
	if len(s) > maxLoggedBody {
		return s[:maxLoggedBody] + fmt.Sprintf("…(truncated, %d bytes total)", len(s))
	}
	return s
}

// fingerprint is a short SHA-256 prefix used to correlate secret material in
// logs without revealing it.
func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}

func newRequestID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// logStartupConfig writes the effective configuration (secrets redacted).
func logStartupConfig(cfg Config) {
	log.Printf("config: addr=%s logLevel=%s tokenTTL=%ds", cfg.Addr, map[bool]string{true: "debug", false: "info"}[debugLogging], cfg.TokenTTLSeconds)
	if cfg.IDPTokenURL == "" {
		log.Printf("config: token mode=LOCAL MOCK (basic user=%q, pass=<%d chars>)", cfg.BasicUser, len(cfg.BasicPass))
	} else {
		log.Printf("config: token mode=IDP PROXY (tokenURL=%s)", cfg.IDPTokenURL)
	}
	if cfg.Verifier == nil {
		log.Printf("config: bearer validation=DISABLED (any non-empty bearer token accepted)")
	} else {
		log.Printf("config: bearer validation=JWKS (jwks=%s issuer=%q audience=%q)",
			cfg.Verifier.jwks.url, cfg.Verifier.issuer, cfg.Verifier.audience)
	}
}

// logKeyInfo describes the loaded RSA key and prints its public half, which is
// what GovPay+ must hold to encrypt the TransactionKey for this GO.
func logKeyInfo(d *Decryptor) {
	pubDER, err := x509.MarshalPKIXPublicKey(&d.priv.PublicKey)
	if err != nil {
		log.Printf("encryption: could not marshal public key: %v", err)
		return
	}
	log.Printf("encryption: RSA key loaded: %d-bit, public exponent=%d, public key sha256=%s",
		d.priv.N.BitLen(), d.priv.E, fingerprint(pubDER))
	if err := d.priv.Validate(); err != nil {
		log.Printf("encryption: WARNING private key failed validation: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	log.Printf("encryption: matching public key (give this to GovPay+):\n%s", strings.TrimSpace(string(pubPEM)))
	log.Printf("encryption: scheme TransactionKey=RSA-OAEP(SHA-256,MGF1-SHA-256) payload=AES-256-CBC/PKCS7 aesKey=SHA-256(transactionKey) IV=aesKey[:16]")
}

// logSampleBills lists the seeded bills so testers know which refNos exist.
func logSampleBills(s *BillStore) {
	bills := s.All()
	log.Printf("bills: %d sample bills loaded", len(bills))
	for _, b := range bills {
		log.Printf("bills:   refNo=%-10s amount=%12s period=%-8s type=%-26q taxpayer=%q",
			b.RefNo, formatAmount(b.Amount), b.BillingPeriod, b.TaxType, b.TaxpayerName)
	}
}

// encryptionSelfTest performs a full round trip with the loaded key — the same
// steps GovPay+ and the GO perform — and logs every intermediate value, plus a
// ready-to-send encrypted sample presentment request. It fails startup if the
// key cannot decrypt what its own public key encrypted.
func encryptionSelfTest(d *Decryptor, s *BillStore) error {
	sampleRef := "ABC123456"
	if _, ok := s.Lookup(sampleRef); !ok {
		if all := s.All(); len(all) > 0 {
			sampleRef = all[0].RefNo
		}
	}

	// 1. GovPay+ side: random 32-char AES key, RSA-OAEP encrypted with our public key.
	aesKey := []byte(randomAlphaNum(aesKeyLen))
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &d.priv.PublicKey, aesKey, nil)
	if err != nil {
		return fmt.Errorf("rsa encrypt: %w", err)
	}
	txnKeyHeader := base64.StdEncoding.EncodeToString(encKey)

	// 2. GO side: decrypt it back.
	got, err := d.DecryptTransactionKey(txnKeyHeader)
	if err != nil {
		return fmt.Errorf("rsa decrypt: %w", err)
	}
	if !bytes.Equal(got, aesKey) {
		return fmt.Errorf("rsa round trip mismatch")
	}
	log.Printf("selftest: RSA-OAEP round trip OK (sample AES key=%q)", aesKey)

	// 3. AES-CBC round trip for each field of a sample data[] item.
	plain := []Param{{Seq: "1", ParamName: "refNo", Value: sampleRef}}
	enc := make([]Param, len(plain))
	for i, p := range plain {
		seq, _ := aesCBCEncrypt(aesKey, p.Seq)
		name, _ := aesCBCEncrypt(aesKey, p.ParamName)
		val, _ := aesCBCEncrypt(aesKey, p.Value.(string))
		enc[i] = Param{Seq: seq, ParamName: name, Value: val}
		log.Printf("selftest: AES-CBC encrypt seq=%q -> %s", p.Seq, seq)
		log.Printf("selftest: AES-CBC encrypt paramName=%q -> %s", p.ParamName, name)
		log.Printf("selftest: AES-CBC encrypt value=%q -> %s", p.Value, val)
	}
	check := append([]Param(nil), enc...)
	if err := d.DecryptParams(check, aesKey); err != nil {
		return fmt.Errorf("aes decrypt: %w", err)
	}
	for i := range check {
		if check[i].Seq != plain[i].Seq || check[i].ParamName != plain[i].ParamName || check[i].Value != plain[i].Value {
			return fmt.Errorf("aes round trip mismatch: got %+v want %+v", check[i], plain[i])
		}
	}
	log.Printf("selftest: AES-256-CBC round trip OK")

	// 4. Show the encrypted response GovPay+ would receive for the sample bill.
	if bill, ok := s.Lookup(sampleRef); ok {
		objs := buildPresentmentData(bill)
		log.Printf("selftest: sample presentment response (plaintext) for %s: %s", sampleRef, toJSON(objs))
		if err := encryptPresentmentValues(objs, aesKey); err != nil {
			return fmt.Errorf("encrypt response: %w", err)
		}
		log.Printf("selftest: sample presentment response (encrypted): %s", toJSON(objs))
	}

	body := toJSON(map[string]interface{}{
		"transactionID": "60562345678995555",
		"subinstId":     "001",
		"serviceid":     "001",
		"serviceName":   "Tax Payment",
		"data":          enc,
	})
	log.Printf("selftest: sample encrypted presentment request for refNo=%s (valid only for this pod's key):", sampleRef)
	log.Printf("selftest:   TransactionKey: %s", txnKeyHeader)
	log.Printf("selftest:   body: %s", body)
	log.Printf("selftest: try it:\n"+
		"curl -k -X POST \"$BASE_URL/api/govpayplus/v1.0/presentment\" -H 'Content-Type: application/json' "+
		"-H \"Authorization: Bearer $ACCESS_TOKEN\" -H 'TransactionKey: %s' -d '%s'", txnKeyHeader, body)
	return nil
}

func randomAlphaNum(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}
