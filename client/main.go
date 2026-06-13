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

type PresentmentObject struct {
	ObjType       string           `json:"objType"`
	Seq           string           `json:"seq"`
	ID            string           `json:"id"`
	Placeholder   string           `json:"placeholder"`
	InitialValue  interface{}      `json:"initialValue"`
	DataType      string           `json:"datatype"`
	MaxLength     int              `json:"maxLength"`
	SelectionType string           `json:"selectionType"`
	Mask          string           `json:"mask"`
	NotNull       string           `json:"notNull"`
	Enabled       string           `json:"enabled"`
	Returned      string           `json:"returned"`
	Rows          int              `json:"rows"`
	Cols          int              `json:"cols"`
	ReturnParam        string           `json:"returnedParam"`
	IsPaymentReference bool             `json:"isPaymentReference,omitempty"`
	IsPaymentAmount    bool             `json:"isPaymentAmount,omitempty"`
	ReturnValue        string           `json:"returnValue"`
	ObjData            []ComboItem      `json:"objData"`
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
	InitialValue  interface{}      `json:"initialValue"`
	DataType      string           `json:"datatype"`
	MaxLength     int              `json:"maxLength"`
	SelectionType string           `json:"selectionType"`
	Mask          string           `json:"mask"`
	NotNull       string           `json:"notNull"`
	Enabled       string           `json:"enabled"`
	Returned      string           `json:"returned"`
	Rows          int              `json:"rows"`
	Cols          int              `json:"cols"`
	ReturnParam   string           `json:"returnedParam"`
	ReturnValue   string           `json:"returnValue"`
	TableData     *TableDataObject `json:"tableData,omitempty"`
}

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/govpayplus/v1.0/generatetoken", generateTokenHandler(cfg))
	mux.HandleFunc("/api/govpayplus/v1.0/presentment", presentmentHandler(cfg))
	mux.HandleFunc("/api/govpayplus/v1.0/update", updateHandler(cfg))

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("GovPay+ GO API listening on %s", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func loadConfig() Config {
	cfg := Config{
		Addr:            getEnv("GOVPAY_ADDR", ":8080"),
		BasicUser:       getEnv("GOVPAY_BASIC_USER", "govpay"),
		BasicPass:       getEnv("GOVPAY_BASIC_PASS", "govpay"),
		TokenTTLSeconds: getEnvInt("GOVPAY_TOKEN_TTL_SECONDS", 3600),
		IDPTokenURL:     getEnv("GOVPAY_IDP_TOKEN_URL", ""),
		Bills:           NewBillStore(),
	}

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

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func generateTokenHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed", Message: "POST required"})
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "Content-Type must be application/x-www-form-urlencoded"})
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "invalid form"})
			return
		}

		// When an IDP token endpoint is configured, forward the caller's
		// Basic-auth credentials to it as client_id/client_secret and relay the
		// IDP's token response.
		if cfg.IDPTokenURL != "" {
			proxyTokenRequest(cfg, w, r)
			return
		}

		// Otherwise issue a local mock token (for local development).
		if !checkBasicAuth(r, cfg.BasicUser, cfg.BasicPass) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: "invalid authorization"})
			return
		}
		if r.FormValue("grant_type") != "client_credentials" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "grant_type must be client_credentials"})
			return
		}

		resp := TokenResponse{
			AccessToken: newToken(),
			Scope:       "default",
			TokenType:   "Bearer",
			ExpiresIn:   cfg.TokenTTLSeconds,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// proxyTokenRequest forwards a client_credentials token request to the
// configured IDP, passing the caller's Basic-auth header through as the IDP
// client credentials, and relays the IDP's response verbatim.
func proxyTokenRequest(cfg Config, w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: "Basic authorization required"})
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
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "server_error", Message: "could not build IDP request"})
		return
	}
	idpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	idpReq.Header.Set("Accept", "application/json")
	idpReq.Header.Set("Authorization", auth) // forward client_id:client_secret

	idpResp, err := idpHTTPClient.Do(idpReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: "bad_gateway", Message: "could not reach IDP token endpoint"})
		return
	}
	defer idpResp.Body.Close()

	body, err := io.ReadAll(idpResp.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: "bad_gateway", Message: "could not read IDP response"})
		return
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
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed", Message: "POST required"})
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "Content-Type must be application/json"})
			return
		}
		if err := authorizeBearer(cfg, r); err != nil {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: err.Error()})
			return
		}
		if r.Header.Get("TransactionKey") == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "missing TransactionKey"})
			return
		}

		req, err := parsePresentmentRequest(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: err.Error()})
			return
		}

		refNo, err := validateRefNoOnly(req.Data)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: err.Error()})
			return
		}

		bill, ok := cfg.Bills.Lookup(refNo)
		if !ok {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "invalid_reference", Message: "invalid reference number"})
			return
		}
		if cfg.Bills.IsPaid(refNo) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "already_paid", Message: "payment already completed for this reference number"})
			return
		}

		resp := PresentmentResponse{
			TransactionID:   req.TransactionID,
			SubInstID:       req.SubInstID,
			ServiceID:       req.ServiceID,
			ServiceName:     req.ServiceName,
			Message:         "Success",
			PresentmentData: buildPresentmentData(bill),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func updateHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed", Message: "POST required"})
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "Content-Type must be application/json"})
			return
		}
		if err := authorizeBearer(cfg, r); err != nil {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: err.Error()})
			return
		}
		if r.Header.Get("TransactionKey") == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "missing TransactionKey"})
			return
		}

		req, err := parsePresentmentRequest(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: err.Error()})
			return
		}

		refNo := findRefNo(req.Data)
		if refNo == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "refNo is required"})
			return
		}
		if _, ok := cfg.Bills.Lookup(refNo); !ok {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "invalid_reference", Message: "invalid reference number"})
			return
		}
		// MarkPaid is atomic and returns false if the bill was already paid,
		// which prevents a second (double) payment for the same refNo.
		if !cfg.Bills.MarkPaid(refNo) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "already_paid", Message: "payment already completed for this reference number"})
			return
		}

		resp := UpdateResponse{
			TransactionID: req.TransactionID,
			SubInstID:     req.SubInstID,
			ServiceID:     req.ServiceID,
			ServiceName:   req.ServiceName,
			Message:       "Success",
			PaymentData:   buildPaymentData(req.Data, req.TransactionID),
		}
		writeJSON(w, http.StatusOK, resp)
	}
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

func isAlphaNumeric(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return s != ""
}

// buildPresentmentData returns the fields to display in the GovPay+ UI for a
// given bill. The amount is presented (enabled=false) and echoed back to the GO
// in the update request (returned=true, returnedParam="amount").
func buildPresentmentData(bill *BillRecord) []PresentmentObject {
	return []PresentmentObject{
		newPresentmentObject(1, "label", "Reference Number", bill.RefNo, "text", refNoMaxLength, false, true, "refNo", true, false),
		newPresentmentObject(2, "label", "Taxpayer Name", bill.TaxpayerName, "text", 50, false, false, "", false, false),
		newPresentmentObject(3, "label", "Tax Type", bill.TaxType, "text", 50, false, false, "", false, false),
		newPresentmentObject(4, "label", "Billing Period", bill.BillingPeriod, "text", 50, false, false, "", false, false),
		newPresentmentObject(5, "textBox", "Amount To Be Paid (LKR)", bill.Amount, "decimal", 13, false, true, "amount", false, true),
	}
}

// newPresentmentObject builds a single presentment object with the common
// defaults from the GovPay+ spec (§2.4.3.2), varying only the fields a caller
// cares about.
func newPresentmentObject(seq int, objType, placeholder string, initialValue interface{}, dataType string, maxLength int, enabled, returned bool, returnParam string, isPaymentReference, isPaymentAmount bool) PresentmentObject {
	return PresentmentObject{
		ObjType:       objType,
		Seq:           strconv.Itoa(seq),
		ID:            fmt.Sprintf("%03d%04d", seq, seq),
		Placeholder:   placeholder,
		InitialValue:  initialValue,
		DataType:      dataType,
		MaxLength:     maxLength,
		SelectionType: "SINGLE",
		Mask:          "",
		NotNull:       "true",
		Enabled:       boolToFlag(enabled),
		Returned:      boolToFlag(returned),
		Rows:          1,
		Cols:          1,
		ReturnParam:        returnParam,
		IsPaymentReference: isPaymentReference,
		IsPaymentAmount:    isPaymentAmount,
		ReturnValue:        "",
		ObjData:            []ComboItem{},
	}
}

func isDecimalValue(value interface{}) bool {
	switch value.(type) {
	case float32, float64, int, int32, int64, uint, uint32, uint64:
		return true
	default:
		return false
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

		items = append(items, PaymentItem{
			ObjType:       "label",
			Seq:           seq,
			ID:            fmt.Sprintf("%03d%04d", i+1, i+1),
			Placeholder:   paramName,
			InitialValue:  param.Value,
			DataType:      valueDataType(param.Value),
			MaxLength:     50,
			SelectionType: "SINGLE",
			Mask:          "",
			NotNull:       "true",
			Enabled:       "false",
			Returned:      "false",
			Rows:          1,
			Cols:          1,
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
		MaxLength:     50,
		SelectionType: "SINGLE",
		Mask:          "",
		NotNull:       "true",
		Enabled:       "false",
		Returned:      "false",
		Rows:          1,
		Cols:          1,
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
		MaxLength:     50,
		SelectionType: "SINGLE",
		Mask:          "",
		NotNull:       "true",
		Enabled:       "false",
		Returned:      "false",
		Rows:          1,
		Cols:          1,
		ReturnParam:   "",
		ReturnValue:   "",
	})

	return items
}

func valueDataType(value interface{}) string {
	if isDecimalValue(value) {
		return "decimal"
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
