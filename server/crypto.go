package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Encryptor implements the GovPay+ side of the data-encryption scheme
// (spec §3). For each call it:
//
//  1. generates a fresh 32-character AES-256 transaction key;
//  2. RSA-OAEP encrypts that key with the GO's public key (the
//     "TransactionKey" header, base64);
//  3. AES-256-CBC encrypts every field (seq, paramName, value) of each
//     request data[] element;
//  4. decrypts every field of each response object with the same AES key.
//
// Algorithm standards (spec §3.2):
//   - TransactionKey: RSA / OAEP (SHA-256) / MGF1(SHA-256) / 2048-bit.
//   - Payload:        AES / CBC / 256-bit, PKCS7 padding, with
//     AES key = SHA-256(transaction key) and IV = first 16 bytes of that key.
type Encryptor struct {
	pub *rsa.PublicKey
}

// aesKeyLen is the length, in bytes, of the plaintext AES-256 transaction key
// (a "32-character" key per spec §3.1).
const aesKeyLen = 32

// ivLen is the AES-CBC IV length. The IV is the first 16 bytes of the derived
// AES key, SHA-256(transaction key) — see deriveAESKey.
const ivLen = 16

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

// EncryptParams encrypts every field (seq, paramName, value) of each request
// data[] item in place with AES-256-CBC (spec §3.1: all three are encrypted).
func EncryptParams(params []Param, key []byte) error {
	for i := range params {
		seq, err := aesCBCEncrypt(key, params[i].Seq)
		if err != nil {
			return err
		}
		params[i].Seq = seq

		name, err := aesCBCEncrypt(key, params[i].ParamName)
		if err != nil {
			return err
		}
		params[i].ParamName = name

		val, err := aesCBCEncrypt(key, valueToString(params[i].Value))
		if err != nil {
			return err
		}
		params[i].Value = val
	}
	return nil
}

// decryptPresentmentValues decrypts every field of every response object in
// place (the GO encrypts them all with the transaction key, spec §3.1.7).
func decryptPresentmentValues(objs []PresentmentObject, key []byte) error {
	for i := range objs {
		if err := decryptPresentmentObject(&objs[i], key); err != nil {
			return err
		}
	}
	return nil
}

func decryptPresentmentObject(o *PresentmentObject, key []byte) error {
	if err := decryptFields(key,
		&o.ObjType, &o.Seq, &o.ID, &o.Placeholder, &o.InitialValue,
		&o.DataType, &o.MaxLength, &o.SelectionType, &o.Mask, &o.NotNull,
		&o.Enabled, &o.Returned, &o.Rows, &o.Cols, &o.ReturnParam,
		&o.IsPaymentReference, &o.IsPaymentAmount, &o.ReturnValue,
	); err != nil {
		return err
	}
	for j := range o.ObjData {
		if err := decryptFields(key, &o.ObjData[j].ID, &o.ObjData[j].Data); err != nil {
			return err
		}
	}
	if o.TableData != nil {
		for j := range o.TableData.Header {
			if err := decryptFields(key, &o.TableData.Header[j].DataType, &o.TableData.Header[j].Value, &o.TableData.Header[j].Enabled); err != nil {
				return err
			}
		}
		for j := range o.TableData.RowData {
			if err := decryptFields(key, &o.TableData.RowData[j].DataType, &o.TableData.RowData[j].Value, &o.TableData.RowData[j].Enabled); err != nil {
				return err
			}
		}
	}
	return nil
}

// decryptFields decrypts each referenced base64 AES-CBC field in place.
func decryptFields(key []byte, fields ...*string) error {
	for _, f := range fields {
		plain, err := decryptField(key, *f)
		if err != nil {
			return err
		}
		*f = plain
	}
	return nil
}

// decryptField decrypts a single base64 AES-CBC field. A field the GO omitted
// entirely arrives as "" and is passed through unchanged (a spec "encrypted
// empty string" is non-empty ciphertext, so this only skips absent fields).
func decryptField(key []byte, b64 string) (string, error) {
	if b64 == "" {
		return "", nil
	}
	return aesCBCDecrypt(key, b64)
}

// valueToString renders a request value as the plaintext to encrypt: strings
// pass through unchanged; other scalars use their default string form. Request
// values are strings in practice (refNo, echoed amount, status).
func valueToString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

// aesCBCEncrypt encrypts plaintext with AES-256-CBC and PKCS7 padding, using
// IV = key[:16] (spec §3.2.2), and returns the base64 of the ciphertext.
func aesCBCEncrypt(key []byte, plaintext string) (string, error) {
	block, iv, err := newCBC(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// aesCBCDecrypt reverses aesCBCEncrypt.
func aesCBCDecrypt(key []byte, b64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("value not base64: %w", err)
	}
	block, iv, err := newCBC(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a whole number of blocks")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	unpadded, err := pkcs7Unpad(plaintext, block.BlockSize())
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

// deriveAESKey turns the 32-character transaction key into the actual AES-256
// key: SHA-256 of the transaction key bytes. This matches what GovPay+ does in
// practice (verified against a live GovPay+ request), even though the spec
// reads as if the transaction key were used directly.
func deriveAESKey(txnKey []byte) []byte {
	sum := sha256.Sum256(txnKey)
	return sum[:]
}

// newCBC returns an AES-256 cipher block keyed with SHA-256(txnKey) and the IV
// (first 16 bytes of that derived key).
func newCBC(txnKey []byte) (cipher.Block, []byte, error) {
	if len(txnKey) != aesKeyLen {
		return nil, nil, fmt.Errorf("aes key must be %d bytes", aesKeyLen)
	}
	key := deriveAESKey(txnKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	return block, key[:ivLen], nil
}

// pkcs7Pad appends PKCS7 padding so the data is a whole number of blocks.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// pkcs7Unpad removes and validates PKCS7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length")
	}
	pad := int(data[n-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range data[n-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:n-pad], nil
}
