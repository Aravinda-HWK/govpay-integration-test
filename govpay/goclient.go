package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GOClient calls a Government Organization (GO) API the way GovPay+ does:
// optionally obtaining a bearer token first, then posting presentment/update
// requests with the encrypted-transaction-key header.
type GOClient struct {
	http *http.Client
}

func NewGOClient() *GOClient {
	return &GOClient{http: &http.Client{Timeout: 15 * time.Second}}
}

// --- Wire types (mirror the GO API in ../client) ---

type Param struct {
	Seq       string      `json:"seq"`
	ParamName string      `json:"paramName"`
	Value     interface{} `json:"value"`
}

type goRequest struct {
	TransactionID string  `json:"transactionID"`
	SubInstID     string  `json:"subinstId"`
	ServiceID     string  `json:"serviceid"`
	ServiceName   string  `json:"serviceName"`
	Data          []Param `json:"data"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// PresentmentObject and PaymentItem mirror the GO response objects.
type PresentmentObject struct {
	ObjType            string           `json:"objType"`
	Seq                string           `json:"seq"`
	ID                 string           `json:"id"`
	Placeholder        string           `json:"placeholder"`
	InitialValue       interface{}      `json:"initialValue"`
	DataType           string           `json:"datatype"`
	MaxLength          int              `json:"maxLength"`
	SelectionType      string           `json:"selectionType"`
	Mask               string           `json:"mask"`
	NotNull            string           `json:"notNull"`
	Enabled            string           `json:"enabled"`
	Returned           string           `json:"returned"`
	Rows               int              `json:"rows"`
	Cols               int              `json:"cols"`
	ReturnParam        string           `json:"returnedParam"`
	ReturnValue        string           `json:"returnValue"`
	IsPaymentReference bool             `json:"isPaymentReference,omitempty"`
	IsPaymentAmount    bool             `json:"isPaymentAmount,omitempty"`
	ObjData            []ComboItem      `json:"objData"`
	TableData          *TableDataObject `json:"tableData,omitempty"`
}

type ComboItem struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

type TableDataObject struct {
	Header  []TableCell `json:"header"`
	RowData []TableCell `json:"rowData"`
}

type TableCell struct {
	DataType string `json:"dataType,omitempty"`
	Value    string `json:"value"`
	Enabled  string `json:"enabled,omitempty"`
}

type PresentmentResponse struct {
	TransactionID   string              `json:"transactionID"`
	SubInstID       string              `json:"subinstId"`
	ServiceID       string              `json:"serviceid"`
	ServiceName     string              `json:"serviceName"`
	Message         string              `json:"message"`
	PresentmentData []PresentmentObject `json:"presentmentData"`
}

type UpdateResponse struct {
	TransactionID string              `json:"transactionID"`
	SubInstID     string              `json:"subinstId"`
	ServiceID     string              `json:"serviceid"`
	ServiceName   string              `json:"serviceName"`
	Message       string              `json:"message"`
	PaymentData   []PresentmentObject `json:"paymentData"`
}

// GOError carries the HTTP status and message returned by the GO so the UI can
// surface 400/401/404/409 distinctly.
type GOError struct {
	Status  int
	Message string
}

func (e *GOError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("GO returned status %d", e.Status)
	}
	return e.Message
}

// Token obtains a bearer token from the GO's generatetoken endpoint using the
// configured Basic credentials.
func (c *GOClient) Token(ctx context.Context, ep GoEndpoint) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		joinURL(ep.BaseURL, ep.Auth.TokenPath), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic := base64.StdEncoding.EncodeToString([]byte(ep.Auth.ClientID + ":" + ep.Auth.ClientSecret))
	req.Header.Set("Authorization", "Basic "+basic)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("reach token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", &GOError{Status: resp.StatusCode, Message: extractMessage(body, "token request failed")}
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode token: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}
	return tr.AccessToken, nil
}

// Presentment sends a refNo to the GO and returns the fields to display.
func (c *GOClient) Presentment(ctx context.Context, ep GoEndpoint, svc ServiceContext, txnID, bearer, refNo string) (*PresentmentResponse, error) {
	reqBody := goRequest{
		TransactionID: txnID,
		SubInstID:     svc.SubInstID,
		ServiceID:     svc.ServiceID,
		ServiceName:   svc.ServiceName,
		Data:          []Param{{Seq: "1", ParamName: "refNo", Value: refNo}},
	}
	var out PresentmentResponse
	if err := c.post(ctx, joinURL(ep.BaseURL, ep.PresentmentPath), ep, bearer, reqBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update confirms the payment with the GO (webhook). The payment status is
// carried as a data[] item by the caller; params are echoed verbatim (the GO
// compares the amount as the string it returned at validate time).
func (c *GOClient) Update(ctx context.Context, ep GoEndpoint, svc ServiceContext, txnID, bearer string, data []Param) (*UpdateResponse, error) {
	reqBody := goRequest{
		TransactionID: txnID,
		SubInstID:     svc.SubInstID,
		ServiceID:     svc.ServiceID,
		ServiceName:   svc.ServiceName,
		Data:          data,
	}
	var out UpdateResponse
	if err := c.post(ctx, joinURL(ep.BaseURL, ep.UpdatePath), ep, bearer, reqBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GOClient) post(ctx context.Context, fullURL string, ep GoEndpoint, bearer string, body, out interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("TransactionKey", ep.TransactionKey)
	if ep.Auth.Enabled && bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reach GO endpoint: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &GOError{Status: resp.StatusCode, Message: extractMessage(raw, fmt.Sprintf("GO returned %d", resp.StatusCode))}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode GO response: %w", err)
	}
	return nil
}

// extractMessage pulls a human-readable message from a GO error body
// ({"error":...,"message":...}), falling back to a default.
func extractMessage(body []byte, fallback string) string {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil {
		if e.Message != "" {
			return e.Message
		}
		if e.Error != "" {
			return e.Error
		}
	}
	return fallback
}

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}
