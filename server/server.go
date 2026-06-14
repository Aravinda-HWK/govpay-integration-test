package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is the GovPay+ mock: it exposes a JSON API consumed by the React UI
// and orchestrates token / presentment / update calls against the GO plus the
// mock bank transfer.
type Server struct {
	store *Store
	go_   *GOClient

	mu       sync.Mutex
	sessions map[string]*txnSession // keyed by transactionID
}

// paymentStatusSuccess is the status the GO webhook expects on a completed
// payment.
const paymentStatusSuccess = "SUCCESS"

// txnSession holds the presentment result for an in-progress payment so the pay
// step can compute the amount, echo the returned params back to the GO, and
// credit the correct (service-fixed) collection account.
type txnSession struct {
	RefNo       string
	Amount      float64
	ReturnData  []Param
	ServiceCtx  ServiceContext
	DestAccount Account
	Presentment *PresentmentResponse
	CreatedAt   time.Time
}

func NewServer(store *Store) *Server {
	return &Server{
		store:    store,
		go_:      NewGOClient(),
		sessions: make(map[string]*txnSession),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/services", s.handleServices)
	mux.HandleFunc("/api/presentment", s.handlePresentment)
	mux.HandleFunc("/api/pay", s.handlePay)
	mux.Handle("/", spaHandler())
	return logRequest(mux)
}

// --- /api/config ---

type configView struct {
	GoEndpoint GoEndpoint `json:"goEndpoint"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.store.Snapshot()
		writeJSON(w, http.StatusOK, configView{GoEndpoint: cfg.GoEndpoint})
	case http.MethodPut:
		var ep GoEndpoint
		if err := json.NewDecoder(r.Body).Decode(&ep); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid config body")
			return
		}
		if strings.TrimSpace(ep.BaseURL) == "" {
			writeErr(w, http.StatusBadRequest, "baseURL is required")
			return
		}
		if err := s.store.UpdateEndpoint(ep); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		cfg := s.store.Snapshot()
		writeJSON(w, http.StatusOK, configView{GoEndpoint: cfg.GoEndpoint})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET or PUT required")
	}
}

// --- /api/services ---

// handleServices returns the sub-institutions and their services so the UI can
// render the selectors.
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{"subInstitutions": cfg.SubInstitutions})
}

// --- /api/presentment ---

type presentmentBody struct {
	SubInstID string `json:"subInstId"`
	ServiceID string `json:"serviceId"`
	RefNo     string `json:"refNo"`
}

type presentmentResult struct {
	TransactionID string               `json:"transactionId"`
	RefNo         string               `json:"refNo"`
	Amount        float64              `json:"amount"`
	SubInstName   string               `json:"subInstName"`
	ServiceName   string               `json:"serviceName"`
	DestAccount   Account              `json:"destAccount"`
	Presentment   *PresentmentResponse `json:"presentment"`
}

func (s *Server) handlePresentment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body presentmentBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	refNo := strings.TrimSpace(body.RefNo)
	if refNo == "" {
		writeErr(w, http.StatusBadRequest, "refNo is required")
		return
	}
	sub, svc, ok := s.store.FindService(body.SubInstID, body.ServiceID)
	if !ok {
		writeErr(w, http.StatusBadRequest, "select a valid sub-institution and service")
		return
	}
	svcCtx := ServiceContext{SubInstID: sub.ID, ServiceID: svc.ID, ServiceName: svc.Name}

	cfg := s.store.Snapshot()
	bearer, err := s.bearer(r, cfg.GoEndpoint)
	if err != nil {
		writeGOErr(w, err)
		return
	}

	txnID := newTransactionID()
	resp, err := s.go_.Presentment(r.Context(), cfg.GoEndpoint, svcCtx, txnID, bearer, refNo)
	if err != nil {
		writeGOErr(w, err)
		return
	}

	amount, returnData := extractReturnData(resp.PresentmentData, refNo)
	s.mu.Lock()
	s.sessions[txnID] = &txnSession{
		RefNo:       refNo,
		Amount:      amount,
		ReturnData:  returnData,
		ServiceCtx:  svcCtx,
		DestAccount: svc.Account,
		Presentment: resp,
		CreatedAt:   time.Now(),
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, presentmentResult{
		TransactionID: txnID,
		RefNo:         refNo,
		Amount:        amount,
		SubInstName:   sub.Name,
		ServiceName:   svc.Name,
		DestAccount:   svc.Account,
		Presentment:   resp,
	})
}

// --- /api/pay ---

type payBody struct {
	TransactionID string `json:"transactionId"`
}

type payResult struct {
	TransactionID string          `json:"transactionId"`
	Amount        float64         `json:"amount"`
	DestAccount   Account         `json:"destAccount"`
	Update        *UpdateResponse `json:"update"`
}

func (s *Server) handlePay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body payBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.mu.Lock()
	sess, ok := s.sessions[body.TransactionID]
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or expired transaction; run presentment first")
		return
	}
	if sess.Amount <= 0 {
		writeErr(w, http.StatusBadRequest, "no payable amount found in presentment data")
		return
	}

	// Confirm the payment with the GO (this marks the bill paid). The source
	// account is handled by the bank app this UI lives inside, so there is no
	// account selection here.
	cfg := s.store.Snapshot()
	bearer, err := s.bearer(r, cfg.GoEndpoint)
	if err != nil {
		writeGOErr(w, err)
		return
	}
	// The webhook requires the payment outcome as a "status" data item.
	updateData := append([]Param(nil), sess.ReturnData...)
	updateData = append(updateData, Param{
		Seq:       strconv.Itoa(len(updateData) + 1),
		ParamName: "status",
		Value:     paymentStatusSuccess,
	})
	upd, err := s.go_.Update(r.Context(), cfg.GoEndpoint, sess.ServiceCtx, body.TransactionID, bearer, updateData)
	if err != nil {
		writeGOErr(w, err)
		return
	}

	s.mu.Lock()
	delete(s.sessions, body.TransactionID)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, payResult{
		TransactionID: body.TransactionID,
		Amount:        sess.Amount,
		DestAccount:   sess.DestAccount,
		Update:        upd,
	})
}

// bearer returns the token to use for GO calls: from the configured token
// endpoint when auth is enabled, or "" when auth is disabled.
func (s *Server) bearer(r *http.Request, ep GoEndpoint) (string, error) {
	if !ep.Auth.Enabled {
		return "", nil
	}
	return s.go_.Token(r.Context(), ep)
}

// extractReturnData walks the presentment objects and builds the data[] to echo
// back in the update request: every object with returned=="true" contributes a
// {returnedParam: initialValue} pair. It also returns the payable amount (the
// object flagged isPaymentAmount, or paramName "amount").
func extractReturnData(objs []PresentmentObject, refNo string) (float64, []Param) {
	var amount float64
	var data []Param
	seq := 1
	for _, o := range objs {
		if !strings.EqualFold(o.Returned, "true") {
			continue
		}
		param := strings.TrimSpace(o.ReturnParam)
		if param == "" {
			continue
		}
		// Echo the value exactly as the GO returned it at validate time — the
		// webhook compares the amount as a string, so converting it to a number
		// here causes a "payment amount mismatch".
		if o.IsPaymentAmount || strings.EqualFold(param, "amount") {
			amount = toFloat(o.InitialValue)
		}
		data = append(data, Param{Seq: strconv.Itoa(seq), ParamName: param, Value: o.InitialValue})
		seq++
	}
	// Guarantee the GO can resolve the bill even if no object was flagged.
	if !hasParam(data, "refNo") {
		data = append([]Param{{Seq: "0", ParamName: "refNo", Value: refNo}}, data...)
	}
	return amount, data
}

func hasParam(data []Param, name string) bool {
	for _, p := range data {
		if strings.EqualFold(p.ParamName, name) {
			return true
		}
	}
	return false
}

func toFloat(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f
	default:
		return 0
	}
}

// --- helpers ---

func newTransactionID() string {
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	var sb strings.Builder
	for _, b := range buf {
		sb.WriteString(strconv.Itoa(int(b) % 10))
		sb.WriteString(strconv.Itoa(int(b>>4) % 10))
	}
	return sb.String()[:18]
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

// writeGOErr maps a GOClient error to an HTTP response, preserving the GO's
// status code when available.
func writeGOErr(w http.ResponseWriter, err error) {
	var ge *GOError
	if errors.As(err, &ge) {
		writeErr(w, ge.Status, ge.Error())
		return
	}
	writeErr(w, http.StatusBadGateway, err.Error())
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
