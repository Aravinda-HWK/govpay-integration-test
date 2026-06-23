package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
)

func testDecryptor(t *testing.T) *Decryptor {
	t.Helper()
	d, err := loadDecryptor("keys/go_private.pem")
	if err != nil {
		t.Fatalf("loadDecryptor: %v", err)
	}
	return d
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	const plain = "ABC123456"
	ct, err := aesGCMEncrypt(key, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := aesGCMDecrypt(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("got %q, want %q", got, plain)
	}
}

// TestDecryptTransactionKey verifies the GO decrypts an RSA-OAEP/SHA-256
// transaction key that was encrypted with its public key (spec §3.2.1).
func TestDecryptTransactionKey(t *testing.T) {
	d := testDecryptor(t)
	pub := loadTestPublicKey(t)

	aesKey := make([]byte, aesKeyLen)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	header := base64.StdEncoding.EncodeToString(ct)

	got, err := d.DecryptTransactionKey(header)
	if err != nil {
		t.Fatalf("DecryptTransactionKey: %v", err)
	}
	if string(got) != string(aesKey) {
		t.Fatal("decrypted AES key mismatch")
	}
}

// TestDecryptTransactionKeyRejectsPlaintext ensures a clear-text key (the old
// behavior) fails decryption so the handler can return 401 (spec §3.1.6).
func TestDecryptTransactionKeyRejectsPlaintext(t *testing.T) {
	d := testDecryptor(t)
	if _, err := d.DecryptTransactionKey("12345678901234567890123456789012"); err == nil {
		t.Fatal("expected error decrypting plaintext transaction key")
	}
}

func TestDecryptValuesInPlace(t *testing.T) {
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	ct, _ := aesGCMEncrypt(key, "ABC123456")
	params := []Param{{Seq: "1", ParamName: "refNo", Value: ct}}
	d := &Decryptor{}
	if err := d.DecryptValues(params, key); err != nil {
		t.Fatalf("DecryptValues: %v", err)
	}
	if params[0].Value != "ABC123456" {
		t.Fatalf("got %v, want ABC123456", params[0].Value)
	}
}

func loadTestPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	data, err := os.ReadFile("../server/keys/go_public.pem")
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	block, _ := pem.Decode(data)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return pub.(*rsa.PublicKey)
}
