package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// Encryptor implements the GovPay+ side of the data-encryption scheme
// (spec §3). For each call it:
//
//  1. generates a fresh 32-character AES-256 transaction key;
//  2. RSA-OAEP encrypts that key with the GO's public key (the
//     "TransactionKey" header, base64);
//  3. AES-256-GCM encrypts each data[].value of the request;
//  4. decrypts the response values with the same AES key.
//
// Algorithm standards (spec §3.2):
//   - TransactionKey: RSA / OAEP (SHA-256) / 2048-bit.
//   - Payload:        AES / GCM / 256-bit, IV = first 12 bytes of the AES key.
type Encryptor struct {
	pub *rsa.PublicKey
}

// aesKeyLen is the length, in bytes, of the plaintext AES-256 transaction key
// (a "32-character" key per spec §3.1).
const aesKeyLen = 32

// gcmNonceLen is the GCM IV length: "First 12 bytes of cryptographic key"
// (spec §3.2.2).
const gcmNonceLen = 12

// keyAlphabet is the printable ASCII alphabet used to build the 32-character
// transaction key, so it is safe to log/inspect as plain text per spec §3.1.1.
const keyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// NewEncryptor parses a PEM-encoded RSA public key (X.509 / SubjectPublicKeyInfo
// or PKCS#1).
func NewEncryptor(pemData []byte) (*Encryptor, error) {
	pub, err := parseRSAPublicKey(pemData)
	if err != nil {
		return nil, err
	}
	return &Encryptor{pub: pub}, nil
}

func parseRSAPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("public key: no PEM block found")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("public key is not RSA")
	}
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub, nil
	}
	return nil, fmt.Errorf("parse public key: unsupported format")
}

// NewTransactionKey returns a fresh 32-character (256-bit) AES key as plain
// text bytes.
func NewTransactionKey() ([]byte, error) {
	buf := make([]byte, aesKeyLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	for i := range buf {
		buf[i] = keyAlphabet[int(buf[i])%len(keyAlphabet)]
	}
	return buf, nil
}

// EncryptTransactionKey RSA-OAEP encrypts the AES key for the "TransactionKey"
// header and returns it base64-encoded.
func (e *Encryptor) EncryptTransactionKey(aesKey []byte) (string, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, e.pub, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("rsa encrypt transaction key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// EncryptValues encrypts the value of every data[] item in place (string form,
// base64 AES-GCM).
func EncryptValues(params []Param, key []byte) error {
	for i := range params {
		enc, err := aesGCMEncrypt(key, valueToString(params[i].Value))
		if err != nil {
			return err
		}
		params[i].Value = enc
	}
	return nil
}

// decryptPresentmentValues decrypts the InitialValue of every response object
// in place (the GO encrypts them with the same transaction key, spec §3.1.7).
func decryptPresentmentValues(objs []PresentmentObject, key []byte) error {
	for i := range objs {
		plain, err := decryptInitialValue(objs[i].InitialValue, key)
		if err != nil {
			return err
		}
		objs[i].InitialValue = plain
	}
	return nil
}

func decryptInitialValue(v interface{}, key []byte) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("encrypted initialValue must be a string")
	}
	return aesGCMDecrypt(key, s)
}

// valueToString renders a JSON value as the plaintext to encrypt: strings pass
// through unchanged, everything else is JSON-encoded (so 1000.00 -> "1000").
func valueToString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM using nonce = key[:12]
// (spec §3.2.2) and returns the base64 of (ciphertext||tag).
func aesGCMEncrypt(key []byte, plaintext string) (string, error) {
	gcm, nonce, err := newGCM(key)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// aesGCMDecrypt reverses aesGCMEncrypt.
func aesGCMDecrypt(key []byte, b64 string) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("value not base64: %w", err)
	}
	gcm, nonce, err := newGCM(key)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("gcm open: %w", err)
	}
	return string(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, []byte, error) {
	if len(key) != aesKeyLen {
		return nil, nil, fmt.Errorf("aes key must be %d bytes", aesKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceLen)
	if err != nil {
		return nil, nil, err
	}
	return gcm, key[:gcmNonceLen], nil
}
