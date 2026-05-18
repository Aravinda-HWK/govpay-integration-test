package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	TransactionID   string              `json:"transactionId"`
	SubInstID       string              `json:"subinstId"`
	ServiceID       string              `json:"serviceId"`
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
	ReturnParam   string           `json:"returnParam"`
	ReturnValue   string           `json:"returnValue"`
	ObjData       []ComboItem      `json:"objData"`
	TableData     *TableDataObject `json:"tableData,omitempty"`
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
	TransactionID string        `json:"transactionId"`
	SubInstID     string        `json:"subinstId"`
	ServiceID     string        `json:"serviceId"`
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
	ReturnParam   string           `json:"returnParam"`
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
		if !checkBasicAuth(r, cfg.BasicUser, cfg.BasicPass) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: "invalid authorization"})
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad_request", Message: "invalid form"})
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
		if !checkBearerAuth(r) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: "missing bearer token"})
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

		resp := PresentmentResponse{
			TransactionID:   req.TransactionID,
			SubInstID:       req.SubInstID,
			ServiceID:       req.ServiceID,
			ServiceName:     req.ServiceName,
			Message:         "Success",
			PresentmentData: buildPresentmentData(req.Data),
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
		if !checkBearerAuth(r) {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthorized", Message: "missing bearer token"})
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

	transactionID, ok, err := getStringField(payload, "transactionId")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("transactionId required")
	}

	subInstID, ok, err := getStringField(payload, "subinstId", "suinstId")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("subinstId required")
	}

	serviceID, ok, err := getStringField(payload, "serviceId", "serviced")
	if err != nil {
		return PresentmentRequest{}, err
	}
	if !ok {
		return PresentmentRequest{}, fmt.Errorf("serviceId required")
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

func buildPresentmentData(params []Param) []PresentmentObject {
	objects := make([]PresentmentObject, 0, len(params))
	for i, param := range params {
		seq := strings.TrimSpace(param.Seq)
		if seq == "" {
			seq = fmt.Sprintf("%d", i+1)
		}
		paramName := strings.TrimSpace(param.ParamName)
		if paramName == "" {
			paramName = fmt.Sprintf("param_%d", i+1)
		}

		dataType := "text"
		objType := "label"
		maxLength := 50
		if isDecimalValue(param.Value) || strings.Contains(strings.ToLower(paramName), "amount") {
			dataType = "decimal"
			objType = "textbox"
			maxLength = 13
		}

		objects = append(objects, PresentmentObject{
			ObjType:       objType,
			Seq:           seq,
			ID:            fmt.Sprintf("%03d%04d", i+1, i+1),
			Placeholder:   paramName,
			InitialValue:  param.Value,
			DataType:      dataType,
			MaxLength:     maxLength,
			SelectionType: "SINGLE",
			Mask:          "",
			NotNull:       "true",
			Enabled:       boolToFlag(objType == "textbox"),
			Returned:      "true",
			Rows:          1,
			Cols:          1,
			ReturnParam:   paramName,
			ReturnValue:   "",
			ObjData:       []ComboItem{},
		})
	}
	return objects
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

func checkBearerAuth(r *http.Request) bool {
	const prefix = "Bearer "
	return strings.HasPrefix(r.Header.Get("Authorization"), prefix)
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
