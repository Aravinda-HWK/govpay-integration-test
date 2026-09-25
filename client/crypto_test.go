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

// TestAESCBCRoundTrip verifies AES-256-CBC + PKCS7 with IV = key[:16]
// (spec §3.2.2) over a range of plaintext lengths, including empty and
// block-aligned inputs.
func TestAESCBCRoundTrip(t *testing.T) {
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{
		"", "1", "refNo", "ABC123456",
		"1234567890123456",  // exactly one block
		"12345678901234567", // one byte into a second block
		"24000.00",
	} {
		ct, err := aesCBCEncrypt(key, plain)
		if err != nil {
			t.Fatalf("encrypt %q: %v", plain, err)
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

// TestAESCBCIVIsDerivedKeyPrefix asserts the IV is the first 16 bytes of the
// derived AES key, SHA-256(transaction key).
func TestAESCBCIVIsDerivedKeyPrefix(t *testing.T) {
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, iv, err := newCBC(key)
	if err != nil {
		t.Fatalf("newCBC: %v", err)
	}
	sum := sha256.Sum256(key)
	if string(iv) != string(sum[:ivLen]) {
		t.Fatal("IV is not the first 16 bytes of SHA-256(transaction key)")
	}
}

// TestDecryptLiveGovPayRequest decrypts fields captured from a real GovPay+
// presentment request (2026-09-25, txn 202008061689) with the transaction key
// recovered from its TransactionKey header.
func TestDecryptLiveGovPayRequest(t *testing.T) {
	key := []byte("20260925045916fbf2e8db6be34901bf")
	for cipherText, want := range map[string]string{
		"RgRSAzT/ozEpkY4iixh1oA==": "1",
		"qmSrayjMwoQ23dPqAI3mRQ==": "refNo",
		"KKbC+bDkHMPm6rO4+dcNWA==": "1234",
	} {
		got, err := aesCBCDecrypt(key, cipherText)
		if err != nil {
			t.Fatalf("decrypt %s: %v", cipherText, err)
		}
		if got != want {
			t.Fatalf("decrypt %s = %q, want %q", cipherText, got, want)
		}
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

// TestDecryptParamsInPlace verifies that seq, paramName and value of each
// request item are all decrypted (spec §3.1: GovPay+ encrypts all three).
func TestDecryptParamsInPlace(t *testing.T) {
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encSeq, _ := aesCBCEncrypt(key, "1")
	encName, _ := aesCBCEncrypt(key, "refNo")
	encVal, _ := aesCBCEncrypt(key, "ABC123456")
	params := []Param{{Seq: encSeq, ParamName: encName, Value: encVal}}

	d := &Decryptor{}
	if err := d.DecryptParams(params, key); err != nil {
		t.Fatalf("DecryptParams: %v", err)
	}
	if params[0].Seq != "1" || params[0].ParamName != "refNo" || params[0].Value != "ABC123456" {
		t.Fatalf("got %+v, want seq=1 paramName=refNo value=ABC123456", params[0])
	}
}

// TestEncryptPresentmentValuesEveryField verifies every field of a response
// object is encrypted — including empty fields (encrypted empty strings) — and
// that decrypting with the same key restores the plaintext (spec §3.1.7).
func TestEncryptPresentmentValuesEveryField(t *testing.T) {
	key := make([]byte, aesKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	objs := buildPresentmentData(&BillRecord{
		RefNo: "ABC123456", TaxpayerName: "Jane Smith", TaxType: "VAT",
		BillingPeriod: "2026-Q1", Amount: 24000.00,
	})
	if err := encryptPresentmentValues(objs, key); err != nil {
		t.Fatalf("encryptPresentmentValues: %v", err)
	}

	// The amount object (seq 5) carries the payable amount; its InitialValue
	// must round-trip back to the formatted amount string, and its empty
	// fields (mask, returnedValue) must be encrypted empty strings.
	amount := objs[4]
	if amount.Mask == "" || amount.ReturnValue == "" {
		t.Fatal("empty fields should be encrypted, not left blank")
	}
	if got, err := aesCBCDecrypt(key, amount.Mask); err != nil || got != "" {
		t.Fatalf("mask decrypt: got %q err %v, want empty", got, err)
	}
	if got, err := aesCBCDecrypt(key, amount.InitialValue); err != nil || got != "24000.00" {
		t.Fatalf("amount decrypt: got %q err %v, want 24000.00", got, err)
	}
	if got, err := aesCBCDecrypt(key, amount.IsPaymentAmount); err != nil || got != "true" {
		t.Fatalf("isPaymentAmount decrypt: got %q err %v, want true", got, err)
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
