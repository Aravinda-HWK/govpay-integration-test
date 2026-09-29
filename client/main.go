package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr            string
	BasicUser       string
	BasicPass       string
	TokenTTLSeconds int

	// IDPTokenURL, when set, makes /generatetoken proxy the caller's Basic-auth
	// credentials to this IDP token endpoint (client_credentials grant).
	IDPTokenURL string
	// Verifier, when non-nil, validates the bearer token on /presentment and
	// /update against the IDP's JWKS.
	Verifier *idpVerifier

	// Decryptor holds the GO's RSA private key and performs the data-encryption
	// scheme of spec §3 (decrypt the transaction key + request values, encrypt
	// response values). It is always required.
	Decryptor *Decryptor

	// Bills is the registry of valid reference numbers and their payment state.
	Bills *BillStore
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type Param struct {
	Seq       string      `json:"seq"`
	ParamName string      `json:"paramName"`
	Value     interface{} `json:"value"`
}

type PresentmentRequest struct {
	TransactionID string
	SubInstID     string
	ServiceID     string
	ServiceName   string
	Data          []Param
}

type PresentmentResponse struct {
	TransactionID   string              `json:"transactionID"`
	SubInstID       string              `json:"subinstId"`
	ServiceID       string              `json:"serviceid"`
	ServiceName     string              `json:"serviceName"`
	Message         string              `json:"message"`
	PresentmentData []PresentmentObject `json:"presentmentData"`
}

// PresentmentObject fields are all strings on the wire: per spec §3 every field
// of a response object is AES-CBC encrypted (and encrypted output is base64
// text), so numeric/boolean fields carry their string form (e.g. "50", "true")
// before encryption.
type PresentmentObject struct {
	ObjType            string           `json:"objType"`
	Seq                string           `json:"seq"`
	ID                 string           `json:"id"`
	Placeholder        string           `json:"placeholder"`
	InitialValue       string           `json:"initialValue"`
	DataType           string           `json:"datatype"`
	MaxLength          string           `json:"maxLength"`
	SelectionType      string           `json:"selectionType"`
	Mask               string           `json:"mask"`
	NotNull            string           `json:"notNull"`
	Enabled            string           `json:"enabled"`
	Returned           string           `json:"returned"`
	Rows               string           `json:"rows"`
	Cols               string           `json:"cols"`
	ReturnParam        string           `json:"returnedParam"`
	IsPaymentReference string           `json:"isPaymentReference"`
	IsPaymentAmount    string           `json:"isPaymentAmount"`
	ReturnValue        string           `json:"returnedValue"`
	ObjData            []ComboItem      `json:"objData,omitempty"`
	TableData          *TableDataObject `json:"tableData,omitempty"`
}

type ComboItem struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

type TableDataObject struct {
	Header  []TableHeader `json:"header"`
	RowData []TableRow    `json:"rowData"`
}

type TableHeader struct {
	DataType string `json:"dataType,omitempty"`
	Value    string `json:"value"`
	Enabled  string `json:"enabled,omitempty"`
}

type TableRow struct {
	DataType string `json:"dataType"`
	Value    string `json:"value"`
	Enabled  string `json:"enabled"`
}

type UpdateResponse struct {
	TransactionID string        `json:"transactionID"`
	SubInstID     string        `json:"subinstId"`
	ServiceID     string        `json:"serviceid"`
	ServiceName   string        `json:"serviceName"`
	Message       string        `json:"message"`
	PaymentData   []PaymentItem `json:"paymentData"`
}

type PaymentItem struct {
	ObjType       string           `json:"objType"`
	Seq           string           `json:"seq"`
	ID            string           `json:"id"`
	Placeholder   string           `json:"placeholder"`
	InitialValue  string           `json:"initialValue"`
	DataType      string           `json:"datatype"`
	MaxLength     string           `json:"maxLength"`
	SelectionType string           `json:"selectionType"`
	Mask          string           `json:"mask"`
	NotNull       string           `json:"notNull"`
	Enabled       string           `json:"enabled"`
	Returned      string           `json:"returned"`
	Rows          string           `json:"rows"`
	Cols          string           `json:"cols"`
	ReturnParam   string           `json:"returnedParam"`
	ReturnValue   string           `json:"returnedValue"`
	TableData     *TableDataObject `json:"tableData,omitempty"`
}

func main() {
	cfg := loadConfig()
	logStartupConfig(cfg)
	logKeyInfo(cfg.Decryptor)
	logSampleBills(cfg.Bills)
	if err := encryptionSelfTest(cfg.Decryptor, cfg.Bills); err != nil {
		log.Fatalf("selftest: encryption self-test FAILED: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/govpayplus/v1.0/generatetoken", generateTokenHandler(cfg))
	mux.HandleFunc("/api/govpayplus/v1.0/presentment", presentmentHandler(cfg))
	mux.HandleFunc("/api/govpayplus/v1.0/update", updateHandler(cfg))

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("GovPay+ GO API listening on %s (endpoints: /api/govpayplus/v1.0/{generatetoken,presentment,update})", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func loadConfig() Config {
	debugLogging = strings.EqualFold(getEnv("GOVPAY_LOG_LEVEL", "info"), "debug")

	cfg := Config{
		Addr:            getEnv("GOVPAY_ADDR", ":8080"),
		BasicUser:       getEnv("GOVPAY_BASIC_USER", "govpay"),
		BasicPass:       getEnv("GOVPAY_BASIC_PASS", "govpay"),
		TokenTTLSeconds: getEnvInt("GOVPAY_TOKEN_TTL_SECONDS", 3600),
		IDPTokenURL:     getEnv("GOVPAY_IDP_TOKEN_URL", ""),
		Bills:           NewBillStore(),
	}

	// Data encryption (spec §3) is always on: the GO requires its RSA private
	// key to decrypt the transaction key and request values. An inline PEM
	// (GOVPAY_RSA_PRIVATE_KEY) takes precedence over the key file.
	var (
		decryptor *Decryptor
		err       error
		keySource string
	)
	if pemStr := getEnv("GOVPAY_RSA_PRIVATE_KEY", ""); pemStr != "" {
		decryptor, err = newDecryptor([]byte(pemStr))
		keySource = "GOVPAY_RSA_PRIVATE_KEY (inline)"
	} else {
		keyPath := getEnv("GOVPAY_RSA_PRIVATE_KEY_FILE", "keys/go_private.pem")
		if st, statErr := os.Stat(keyPath); statErr == nil {
			log.Printf("encryption: reading RSA private key file %s (%d bytes, mode %s, modified %s)",
				keyPath, st.Size(), st.Mode(), st.ModTime().UTC().Format(time.RFC3339))
		} else {
			log.Printf("encryption: RSA private key file %s not accessible: %v", keyPath, statErr)
		}
		decryptor, err = loadDecryptor(keyPath)
		keySource = keyPath
	}
	if err != nil {
		log.Fatalf("load RSA private key (%s): %v", keySource, err)
	}
	cfg.Decryptor = decryptor
	log.Printf("data encryption enabled (RSA private key=%s)", keySource)

	if jwksURL := getEnv("GOVPAY_IDP_JWKS_URL", ""); jwksURL != "" {
		cfg.Verifier = newIDPVerifier(
			jwksURL,
			getEnv("GOVPAY_IDP_ISSUER", ""),
			getEnv("GOVPAY_IDP_AUDIENCE", ""),
		)
		log.Printf("IDP token validation enabled (jwks=%s)", jwksURL)
	}
	if cfg.IDPTokenURL != "" {
		log.Printf("IDP token proxy enabled (token endpoint=%s)", cfg.IDPTokenURL)
	}

	return cfg
}

func generateTokenHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fail(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", fmt.Errorf("got %s", r.Method))
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			fail(w, r, http.StatusBadRequest, "bad_request", "Content-Type must be application/x-www-form-urlencoded", fmt.Errorf("got %q", r.Header.Get("Content-Type")))
			return
		}
		if err := r.ParseForm(); err != nil {
			fail(w, r, http.StatusBadRequest, "bad_request", "invalid form", err)
			return
		}
		logf(r, "token: grant_type=%q scope=%q", r.FormValue("grant_type"), r.FormValue("scope"))

		// When an IDP token endpoint is configured, forward the caller's
		// Basic-auth credentials to it as client_id/client_secret and relay the
		// IDP's token response.
		if cfg.IDPTokenURL != "" {
			proxyTokenRequest(cfg, w, r)
			return
		}

		// Otherwise issue a local mock token (for local development).
		if !checkBasicAuth(r, cfg.BasicUser, cfg.BasicPass) {
			fail(w, r, http.StatusUnauthorized, "unauthorized", "invalid authorization",
				fmt.Errorf("basic credentials did not match GOVPAY_BASIC_USER (got %s)", redactAuthorization(r.Header.Get("Authorization"))))
			return
		}
		if r.FormValue("grant_type") != "client_credentials" {
			fail(w, r, http.StatusBadRequest, "bad_request", "grant_type must be client_credentials", nil)
			return
		}

		resp := TokenResponse{
			AccessToken: newToken(),
			Scope:       "default",
			TokenType:   "Bearer",
			ExpiresIn:   cfg.TokenTTLSeconds,
		}
		logf(r, "token: issued local mock token (expires_in=%ds)", cfg.TokenTTLSeconds)
		writeJSON(w, http.StatusOK, resp)
	}
}

// proxyTokenRequest forwards a client_credentials token request to the
// configured IDP, passing the caller's Basic-auth header through as the IDP
// client credentials, and relays the IDP's response verbatim.
func proxyTokenRequest(cfg Config, w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		fail(w, r, http.StatusUnauthorized, "unauthorized", "Basic authorization required", fmt.Errorf("authorization header: %s", redactAuthorization(auth)))
		return
	}

	grant := r.FormValue("grant_type")
	if grant == "" {
		grant = "client_credentials"
	}
	form := url.Values{}
	form.Set("grant_type", grant)
	if scope := r.FormValue("scope"); scope != "" {
		form.Set("scope", scope)
	}

	idpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.IDPTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		fail(w, r, http.StatusInternalServerError, "server_error", "could not build IDP request", err)
		return
	}
	idpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	idpReq.Header.Set("Accept", "application/json")
	idpReq.Header.Set("Authorization", auth) // forward client_id:client_secret

	logf(r, "token: proxying to IDP %s (client %s, grant_type=%s)", cfg.IDPTokenURL, redactAuthorization(auth), grant)
	idpStart := time.Now()
	idpResp, err := idpHTTPClient.Do(idpReq)
	if err != nil {
		fail(w, r, http.StatusBadGateway, "bad_gateway", "could not reach IDP token endpoint", err)
		return
	}
	defer idpResp.Body.Close()

	body, err := io.ReadAll(idpResp.Body)
	if err != nil {
		fail(w, r, http.StatusBadGateway, "bad_gateway", "could not read IDP response", err)
		return
	}
	logf(r, "token: IDP responded %d in %s (content-type=%q, %d bytes)",
		idpResp.StatusCode, time.Since(idpStart).Round(time.Millisecond), idpResp.Header.Get("Content-Type"), len(body))
	if idpResp.StatusCode != http.StatusOK {
		logf(r, "ERROR token: IDP rejected the request: %s", truncate(string(body)))
	} else {
		var tok TokenResponse
		if json.Unmarshal(body, &tok) == nil && tok.AccessToken != "" {
			logf(r, "token: IDP issued %s token (expires_in=%d scope=%q) %s", tok.TokenType, tok.ExpiresIn, tok.Scope, jwtSummary(tok.AccessToken))
		}
	}

	contentType := idpResp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(idpResp.StatusCode)
	_, _ = w.Write(body)
}

func presentmentHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aesKey, req, ok := decryptRequest(cfg, w, r, "presentment")
		if !ok {
			return
		}

		refNo, err := validateRefNoOnly(req.Data)
		if err != nil {
			fail(w, r, http.StatusBadRequest, "bad_request", err.Error(), fmt.Errorf("decrypted data=%s", toJSON(req.Data)))
			return
		}

		bill, ok := cfg.Bills.Lookup(refNo)
		if !ok {
			fail(w, r, http.StatusNotFound, "invalid_reference", "invalid reference number", fmt.Errorf("refNo %q is not a known bill (%d bills loaded)", refNo, len(cfg.Bills.All())))
			return
		}
		if cfg.Bills.IsPaid(refNo) {
			fail(w, r, http.StatusConflict, "already_paid", "payment already completed for this reference number", fmt.Errorf("refNo %q already paid", refNo))
			return
		}
		logf(r, "presentment: bill found refNo=%s taxpayer=%q type=%q period=%s amount=%s",
			bill.RefNo, bill.TaxpayerName, bill.TaxType, bill.BillingPeriod, formatAmount(bill.Amount))

		resp := PresentmentResponse{
			TransactionID:   req.TransactionID,
			SubInstID:       req.SubInstID,
			ServiceID:       req.ServiceID,
			ServiceName:     req.ServiceName,
			Message:         "Success",
			PresentmentData: buildPresentmentData(bill),
		}
		debugf(r, "presentment: response (plaintext, before encryption): %s", toJSON(resp))
		// Encrypt the response values with the same AES key (spec §3.1.7).
		if err := encryptPresentmentValues(resp.PresentmentData, aesKey); err != nil {
			fail(w, r, http.StatusInternalServerError, "server_error", "could not encrypt response", err)
			return
		}
		logf(r, "presentment: success txn=%s refNo=%s (%d objects encrypted)", req.TransactionID, refNo, len(resp.PresentmentData))
		writeJSON(w, http.StatusOK, resp)
	}
}

func updateHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aesKey, req, ok := decryptRequest(cfg, w, r, "update")
		if !ok {
			return
		}

		refNo := findRefNo(req.Data)
		if refNo == "" {
			fail(w, r, http.StatusBadRequest, "bad_request", "refNo is required", fmt.Errorf("decrypted data=%s", toJSON(req.Data)))
			return
		}
		bill, ok := cfg.Bills.Lookup(refNo)
		if !ok {
			fail(w, r, http.StatusNotFound, "invalid_reference", "invalid reference number", fmt.Errorf("refNo %q is not a known bill", refNo))
			return
		}
		if amount := findParam(req.Data, "amount"); amount != "" && amount != formatAmount(bill.Amount) {
			logf(r, "update: WARNING amount %q differs from bill amount %s for refNo=%s", amount, formatAmount(bill.Amount), refNo)
		}
		// MarkPaid is atomic and returns false if the bill was already paid,
		// which prevents a second (double) payment for the same refNo.
		if !cfg.Bills.MarkPaid(refNo) {
			fail(w, r, http.StatusConflict, "already_paid", "payment already completed for this reference number", fmt.Errorf("refNo %q already paid", refNo))
			return
		}
		logf(r, "update: refNo=%s marked PAID (txn=%s amount=%s)", refNo, req.TransactionID, findParam(req.Data, "amount"))

		resp := UpdateResponse{
			TransactionID: req.TransactionID,
			SubInstID:     req.SubInstID,
			ServiceID:     req.ServiceID,
			ServiceName:   req.ServiceName,
			Message:       "Success",
			PaymentData:   buildPaymentData(req.Data, req.TransactionID),
		}
		debugf(r, "update: response (plaintext, before encryption): %s", toJSON(resp))
		// Encrypt the response values with the same AES key (spec §3.1.7).
		if err := encryptPaymentValues(resp.PaymentData, aesKey); err != nil {
			fail(w, r, http.StatusInternalServerError, "server_error", "could not encrypt response", err)
			return
		}
		logf(r, "update: success txn=%s refNo=%s (%d items encrypted)", req.TransactionID, refNo, len(resp.PaymentData))
		writeJSON(w, http.StatusOK, resp)
	}
}

// decryptRequest runs the checks shared by /presentment and /update: method,
// content type, bearer token, TransactionKey (RSA) and data[] (AES-CBC). On
// failure it writes the error response and returns ok=false.
func decryptRequest(cfg Config, w http.ResponseWriter, r *http.Request, op string) ([]byte, PresentmentRequest, bool) {
	if r.Method != http.MethodPost {
		fail(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", fmt.Errorf("got %s", r.Method))
		return nil, PresentmentRequest{}, false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, r, http.StatusBadRequest, "bad_request", "Content-Type must be application/json", fmt.Errorf("got %q", r.Header.Get("Content-Type")))
		return nil, PresentmentRequest{}, false
	}
	if err := authorizeBearer(cfg, r); err != nil {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		fail(w, r, http.StatusUnauthorized, "unauthorized", err.Error(), fmt.Errorf("token %s", jwtSummary(token)))
		return nil, PresentmentRequest{}, false
	}
	logf(r, "%s: bearer token accepted", op)

	txnKey := r.Header.Get("TransactionKey")
	if txnKey == "" {
		fail(w, r, http.StatusBadRequest, "bad_request", "missing TransactionKey", nil)
		return nil, PresentmentRequest{}, false
	}

	// Decrypt the transaction key (RSA) then the request fields (AES-CBC).
	// Per spec §3.1.6 a decryption/verification failure is 401, not 400.
	aesKey, err := cfg.Decryptor.DecryptTransactionKey(txnKey)
	if err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthorized", "invalid TransactionKey",
			fmt.Errorf("%v (header %d chars; expect base64 of %d-byte RSA-OAEP-SHA256 ciphertext made with this GO's public key)",
				err, len(txnKey), cfg.Decryptor.priv.Size()))
		return nil, PresentmentRequest{}, false
	}
	logf(r, "%s: TransactionKey decrypted (AES key %d bytes, sha256=%s)", op, len(aesKey), fingerprint(aesKey))
	debugf(r, "%s: transaction key=%q derived AES key SHA-256(txnKey)=%x", op, aesKey, deriveAESKey(aesKey))

	req, err := parsePresentmentRequest(r)
	if err != nil {
		fail(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return nil, PresentmentRequest{}, false
	}
	logf(r, "%s: txn=%s subinstId=%s serviceid=%s serviceName=%q data items=%d",
		op, req.TransactionID, req.SubInstID, req.ServiceID, req.ServiceName, len(req.Data))
	debugf(r, "%s: data (encrypted): %s", op, toJSON(req.Data))

	if err := cfg.Decryptor.DecryptParams(req.Data, aesKey); err != nil {
		fail(w, r, http.StatusUnauthorized, "unauthorized", "could not decrypt request values", err)
		return nil, PresentmentRequest{}, false
	}
	logf(r, "%s: data decrypted: %s", op, toJSON(req.Data))
	return aesKey, req, true
}

func parsePresentmentRequest(r *http.Request) (PresentmentRequest, error) {
	var payload map[string]json.RawMessage
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&payload); err != nil {
		return PresentmentRequest{}, fmt.Errorf("invalid json")
	}

	transactionID, ok, err := getStringField(payload, "transactionID", "transactionId")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("transactionID required")
	}

	subInstID, ok, err := getStringField(payload, "subinstId", "suinstId")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("subinstId required")
	}

	serviceID, ok, err := getStringField(payload, "serviceid", "serviceId", "serviced")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("serviceid required")
	}

	serviceName, ok, err := getStringField(payload, "serviceName")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("serviceName required")
	}

	var data []Param
	if raw, found := payload["data"]; found {
		if err := json.Unmarshal(raw, &data); err != nil {
			return PresentmentRequest{}, fmt.Errorf("invalid data array")
		}
	}

	return PresentmentRequest{
		TransactionID: transactionID,
		SubInstID:     subInstID,
		ServiceID:     serviceID,
		ServiceName:   serviceName,
		Data:          data,
	}, nil
}

// refNoMaxLength is the maximum allowed length of the presentment refNo.
// Per the GovPay+ spec a data[].value is "an" (alphanumeric) with a hard ceiling
// of 50; 20 is the value configured for this service at onboarding.
const refNoMaxLength = 20

// validateRefNoOnly enforces that the presentment request carries exactly one
// data item, named "refNo", whose value is a non-empty alphanumeric string no
// longer than refNoMaxLength. It returns the trimmed refNo on success.
func validateRefNoOnly(params []Param) (string, error) {
	if len(params) != 1 {
		return "", fmt.Errorf("data must contain exactly one item: refNo")
	}
	param := params[0]
	if strings.TrimSpace(param.ParamName) != "refNo" {
		return "", fmt.Errorf("data must contain only refNo")
	}
	refNo, ok := param.Value.(string)
	if !ok {
		return "", fmt.Errorf("refNo must be a string")
	}
	refNo = strings.TrimSpace(refNo)
	if refNo == "" {
		return "", fmt.Errorf("refNo is required")
	}
	if len(refNo) > refNoMaxLength {
		return "", fmt.Errorf("refNo must not exceed %d characters", refNoMaxLength)
	}
	if !isAlphaNumeric(refNo) {
		return "", fmt.Errorf("refNo must be alphanumeric")
	}
	return refNo, nil
}

// findRefNo returns the trimmed value of the data item named "refNo" (echoed
// back by GovPay+ from the presentment response), or "" if it is absent or not
// a string.
func findRefNo(params []Param) string {
	for _, param := range params {
		if strings.TrimSpace(param.ParamName) != "refNo" {
			continue
		}
		if v, ok := param.Value.(string); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// findParam returns the trimmed string value of the named data item, or "".
func findParam(params []Param, name string) string {
	for _, param := range params {
		if strings.TrimSpace(param.ParamName) == name {
			if v, ok := param.Value.(string); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func isAlphaNumeric(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return s != ""
}

// buildPresentmentData returns the fields to display in the GovPay+ UI for a
// given bill. Every field is presented read-only (enabled=false) and echoed back
// to the GO in the update request under its returnedParam; without one GovPay+
// falls back to the object ID (e.g. "0020002"), which then shows on the receipt.
func buildPresentmentData(bill *BillRecord) []PresentmentObject {
	return []PresentmentObject{
		newPresentmentObject(1, "label", "Reference Number", bill.RefNo, "text", refNoMaxLength, false, true, "refNo", true, false),
		newPresentmentObject(2, "label", "Taxpayer Name", bill.TaxpayerName, "text", 50, false, true, "name", false, false),
		newPresentmentObject(3, "label", "Tax Type", bill.TaxType, "text", 50, false, true, "taxType", false, false),
		newPresentmentObject(4, "label", "Billing Period", bill.BillingPeriod, "text", 50, false, true, "billingPeriod", false, false),
		newPresentmentObject(5, "textBox", "Amount To Be Paid (LKR)", formatAmount(bill.Amount), "decimal", 13, false, true, "amount", false, true),
	}
}

// formatAmount renders a monetary amount as a fixed 2-decimal string (e.g.
// 24000 -> "24000.00"). The string form is what gets encrypted and echoed back
// by GovPay+ in the update request.
func formatAmount(amount float64) string {
	return strconv.FormatFloat(amount, 'f', 2, 64)
}

// newPresentmentObject builds a single presentment object with the common
// defaults from the GovPay+ spec (§2.4.3.2), varying only the fields a caller
// cares about.
func newPresentmentObject(seq int, objType, placeholder, initialValue, dataType string, maxLength int, enabled, returned bool, returnParam string, isPaymentReference, isPaymentAmount bool) PresentmentObject {
	return PresentmentObject{
		ObjType:            objType,
		Seq:                strconv.Itoa(seq),
		ID:                 fmt.Sprintf("%03d%04d", seq, seq),
		Placeholder:        placeholder,
		InitialValue:       initialValue,
		DataType:           dataType,
		MaxLength:          strconv.Itoa(maxLength),
		SelectionType:      "SINGLE",
		Mask:               "",
		NotNull:            "true",
		Enabled:            boolToFlag(enabled),
		Returned:           boolToFlag(returned),
		Rows:               "1",
		Cols:               "1",
		ReturnParam:        returnParam,
		IsPaymentReference: boolToFlag(isPaymentReference),
		IsPaymentAmount:    boolToFlag(isPaymentAmount),
		ReturnValue:        "",
	}
}

func buildPaymentData(params []Param, transactionID string) []PaymentItem {
	items := make([]PaymentItem, 0, len(params)+2)
	for i, param := range params {
		seq := strings.TrimSpace(param.Seq)
		if seq == "" {
			seq = fmt.Sprintf("%d", i+1)
		}
		paramName := strings.TrimSpace(param.ParamName)
		if paramName == "" {
			paramName = fmt.Sprintf("param_%d", i+1)
		}
		value, _ := param.Value.(string)

		items = append(items, PaymentItem{
			ObjType:       "label",
			Seq:           seq,
			ID:            fmt.Sprintf("%03d%04d", i+1, i+1),
			Placeholder:   paramName,
			InitialValue:  value,
			DataType:      valueDataType(value),
			MaxLength:     "50",
			SelectionType: "SINGLE",
			Mask:          "",
			NotNull:       "true",
			Enabled:       "false",
			Returned:      "false",
			Rows:          "1",
			Cols:          "1",
			ReturnParam:   "",
			ReturnValue:   "",
		})
	}

	receiptSeq := fmt.Sprintf("%d", len(items)+1)
	items = append(items, PaymentItem{
		ObjType:       "label",
		Seq:           receiptSeq,
		ID:            fmt.Sprintf("%03d%04d", len(items)+1, len(items)+1),
		Placeholder:   "Receipt Number",
		InitialValue:  fmt.Sprintf("REC-%s", transactionID),
		DataType:      "text",
		MaxLength:     "50",
		SelectionType: "SINGLE",
		Mask:          "",
		NotNull:       "true",
		Enabled:       "false",
		Returned:      "false",
		Rows:          "1",
		Cols:          "1",
		ReturnParam:   "",
		ReturnValue:   "",
	})

	statusSeq := fmt.Sprintf("%d", len(items)+1)
	items = append(items, PaymentItem{
		ObjType:       "label",
		Seq:           statusSeq,
		ID:            fmt.Sprintf("%03d%04d", len(items)+1, len(items)+1),
		Placeholder:   "Status",
		InitialValue:  "Payment recorded",
		DataType:      "text",
		MaxLength:     "50",
		SelectionType: "SINGLE",
		Mask:          "",
		NotNull:       "true",
		Enabled:       "false",
		Returned:      "false",
		Rows:          "1",
		Cols:          "1",
		ReturnParam:   "",
		ReturnValue:   "",
	})

	return items
}

// valueDataType classifies a decrypted (string) value for the receipt label:
// a value that looks like a decimal amount (contains a dot and parses as a
// float) is "decimal", everything else is "text".
func valueDataType(value string) string {
	v := strings.TrimSpace(value)
	if strings.Contains(v, ".") {
		if _, err := strconv.ParseFloat(v, 64); err == nil {
			return "decimal"
		}
	}
	return "text"
}

func boolToFlag(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func getStringField(payload map[string]json.RawMessage, keys ...string) (string, bool, error) {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", false, fmt.Errorf("%s must be string", key)
		}
		return value, true, nil
	}
	return "", false, nil
}

func checkBasicAuth(r *http.Request, user, pass string) bool {
	const prefix = "Basic "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] == user && parts[1] == pass
}

// authorizeBearer extracts the bearer token and, when an IDP verifier is
// configured, validates it against the IDP's JWKS. Without a verifier it only
// requires a non-empty bearer token (local development).
func authorizeBearer(cfg Config, r *http.Request) error {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return fmt.Errorf("missing bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	if token == "" {
		return fmt.Errorf("missing bearer token")
	}
	if cfg.Verifier != nil {
		if err := cfg.Verifier.verify(token); err != nil {
			return fmt.Errorf("invalid token: %v", err)
		}
	}
	return nil
}

func newToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().Unix())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
