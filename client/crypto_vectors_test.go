package main

import (
	"encoding/base64"
	"os"
	"testing"
)

// lankaPaySampleRequest is the §3.3 "sample request with encryption" from
// LankaPay. Decrypting it requires the 32-character AES transaction key that
// GovPay+ used to produce it — RSA-encrypted in the TransactionKey header,
// which the sample does not include. Set GOVPAY_TEST_TXN_KEY to that plaintext
// key to actually decrypt and assert; without it the vector is only logged.
//
// The §3.4 sample RESPONSE is deliberately omitted: its initialValue/maxLength
// are invalid base64 ("...abcdef=") and several fields reuse the same
// ciphertext, so it is illustrative placeholder data, not decryptable output.
var lankaPaySampleRequest = []struct {
	field  string
	cipher string
}{
	{"e1.seq", "iV5srRAd6tMGtVpE7Zjtx4DffcRoi/f0mkihreBpBBY="},
	{"e1.paramName", "1MbS++GxJjo7EeE3VEyO62za0uNFiRXAwHPbxi0Z5i4="},
	{"e1.value", "a4sfLzClNCpOyIQH+ua0X5IKi7Rugk+3bceXQt0H7UQ="},
	{"e2.seq", "+iNK9rfSz/d23aybpL+b22lJhWEtuuckzKhVn+U9hqg="},
	{"e2.paramName", "9mTvzwkJZ3g77uIk1I19obnCr4WocO3Iz1bXMaFSnMY="},
	{"e2.value", "+otx9Rlht1yscmeCidMx8z6o8fwkXGEfAtd/tZI2GR8="},
	{"e3.seq", "Hv2fwwzo3tv6dPe4zo6mC1H+sMnat3AiTkKoDgeJ+Ic="},
	{"e3.paramName", "Yq4bJJmvGHbRttApYKKeNI8VbgkT6SkocIX7b7mjVMA="},
	{"e3.value", "vvnN8ErmnC/If5E1HsE2dyWfilIYo/CdV7/0dBEawD4="},
}

// expectedLankaPayPlaintext maps each field to the plaintext we expect once
// decrypted. Fill these in from LankaPay's worked example (spec Q7); any field
// left out (or "") is logged but not asserted.
var expectedLankaPayPlaintext = map[string]string{
	// "e1.seq":       "1",
	// "e1.paramName": "refNo",
	// "e1.value":     "...",
}

// TestLankaPaySampleRequestVector decrypts the §3.3 sample with the transaction
// key from GOVPAY_TEST_TXN_KEY, logging each plaintext and asserting it against
// expectedLankaPayPlaintext. Without the key it logs decode diagnostics and
// skips (the sample carries no key of its own).
func TestLankaPaySampleRequestVector(t *testing.T) {
	// Always log a decode diagnostic so the vector is visible even without a key.
	for _, tc := range lankaPaySampleRequest {
		raw, err := base64.StdEncoding.DecodeString(tc.cipher)
		if err != nil {
			t.Logf("%-13s INVALID base64: %v", tc.field, err)
			continue
		}
		t.Logf("%-13s %d ciphertext bytes (%d AES blocks)", tc.field, len(raw), len(raw)/ivLen)
	}

	keyStr := os.Getenv("GOVPAY_TEST_TXN_KEY")
	if keyStr == "" {
		t.Skip("set GOVPAY_TEST_TXN_KEY to LankaPay's 32-char transaction key to decrypt and assert")
	}
	key := []byte(keyStr)
	if len(key) != aesKeyLen {
		t.Fatalf("GOVPAY_TEST_TXN_KEY must be %d characters, got %d", aesKeyLen, len(key))
	}

	for _, tc := range lankaPaySampleRequest {
		plain, err := aesCBCDecrypt(key, tc.cipher)
		if err != nil {
			t.Errorf("%-13s decrypt failed: %v", tc.field, err)
			continue
		}
		t.Logf("%-13s -> %q", tc.field, plain)
		if want, ok := expectedLankaPayPlaintext[tc.field]; ok && want != "" && plain != want {
			t.Errorf("%s: got %q, want %q", tc.field, plain, want)
		}
	}
}
