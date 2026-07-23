package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
)

// loadTestEncryptor builds an Encryptor from the repo's test GO public key.
func loadTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	data, err := os.ReadFile("keys/go_public.pem")
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	enc, err := NewEncryptor(data)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return enc
}

func TestNewTransactionKeyLength(t *testing.T) {
	key, err := NewTransactionKey()
	if err != nil {
		t.Fatalf("NewTransactionKey: %v", err)
	}
	if len(key) != aesKeyLen {
		t.Fatalf("key length = %d, want %d", len(key), aesKeyLen)
	}
}

// TestAESCBCRoundTrip verifies AES-256-CBC + PKCS7 with IV = key[:16]
// (spec §3.2.2) round-trips across a range of plaintext lengths.
func TestAESCBCRoundTrip(t *testing.T) {
	key, _ := NewTransactionKey()
	for _, plain := range []string{"", "1", "refNo", "ABC123456", "1234567890123456", "24000.00"} {
		ct, err := aesCBCEncrypt(key, plain)
		if err != nil {
			t.Fatalf("encrypt %q: %v", plain, err)
		}
		if plain != "" && ct == plain {
			t.Fatalf("ciphertext equals plaintext for %q", plain)
		}
		got, err := aesCBCDecrypt(key, ct)
		if err != nil {
			t.Fatalf("decrypt %q: %v", plain, err)
		}
		if got != plain {
			t.Fatalf("round trip: got %q, want %q", got, plain)
		}
	}
}

// TestTransactionKeyRSARoundTrip verifies the GovPay+ -> GO transaction-key
// exchange: encrypt with the public key, decrypt with the matching private key
// using RSA-OAEP/SHA-256 (spec §3.2.1).
func TestTransactionKeyRSARoundTrip(t *testing.T) {
	enc := loadTestEncryptor(t)
	key, _ := NewTransactionKey()

	header, err := enc.EncryptTransactionKey(key)
	if err != nil {
		t.Fatalf("EncryptTransactionKey: %v", err)
	}

	priv := loadTestPrivateKey(t)
	ciphertext := mustBase64Decode(t, header)
	got, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ciphertext, nil)
	if err != nil {
		t.Fatalf("DecryptOAEP: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("decrypted key mismatch")
	}
}

// TestEncryptParamsRoundTrip verifies that seq, paramName and value of every
// request item are all encrypted (spec §3.1) and decrypt back to plaintext.
func TestEncryptParamsRoundTrip(t *testing.T) {
	key, _ := NewTransactionKey()
	params := []Param{
		{Seq: "1", ParamName: "refNo", Value: "ABC123456"},
		{Seq: "2", ParamName: "amount", Value: 24000.00},
	}
	if err := EncryptParams(params, key); err != nil {
		t.Fatalf("EncryptParams: %v", err)
	}
	if params[0].ParamName == "refNo" || params[0].Value == "ABC123456" {
		t.Fatal("seq/paramName/value should all be encrypted")
	}

	// seq and paramName round-trip.
	if got, _ := aesCBCDecrypt(key, params[0].Seq); got != "1" {
		t.Fatalf("seq roundtrip: got %q, want 1", got)
	}
	if got, _ := aesCBCDecrypt(key, params[0].ParamName); got != "refNo" {
		t.Fatalf("paramName roundtrip: got %q, want refNo", got)
	}
	v0, err := aesCBCDecrypt(key, params[0].Value.(string))
	if err != nil || v0 != "ABC123456" {
		t.Fatalf("refNo value roundtrip: %q err=%v", v0, err)
	}
	v1, err := aesCBCDecrypt(key, params[1].Value.(string))
	if err != nil || v1 != "24000" {
		t.Fatalf("amount roundtrip: %q err=%v", v1, err)
	}
}

func loadTestPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile("../client/keys/go_private.pem")
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	block, _ := pem.Decode(data)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	return parsed.(*rsa.PrivateKey)
}

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}
