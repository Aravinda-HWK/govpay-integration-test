package main

import "sync"

// BillRecord is the billing detail the GO holds for a single reference number.
// In production these would be looked up from the GO's billing system keyed by
// refNo; here they are seeded into an in-memory registry.
type BillRecord struct {
	RefNo         string
	TaxpayerName  string
	TaxType       string
	BillingPeriod string
	Amount        float64
}

// BillStore is an in-memory registry of valid reference numbers and their
// payment state. It is safe for concurrent use.
//
// NOTE: state lives only in memory, so it is reset on pod restart and is not
// shared across replicas. The deployment runs a single replica; if it is ever
// scaled out or needs to survive restarts, back this with a shared datastore.
type BillStore struct {
	mu    sync.RWMutex
	bills map[string]*BillRecord // keyed by refNo
	paid  map[string]bool        // refNo -> payment completed
}

// NewBillStore returns a store seeded with a fixed set of sample bills.
func NewBillStore() *BillStore {
	seed := []*BillRecord{
		{RefNo: "12345", TaxpayerName: "John Doe", TaxType: "Income Tax", BillingPeriod: "2026-Q1", Amount: 1500.50},
		{RefNo: "ABC123456", TaxpayerName: "Jane Smith", TaxType: "VAT", BillingPeriod: "2026-Q1", Amount: 24000.00},
		{RefNo: "FCAU0001", TaxpayerName: "Acme Pvt Ltd", TaxType: "FCAU Application Fee", BillingPeriod: "2026", Amount: 5000.00},
		{RefNo: "TAX2026", TaxpayerName: "Saman Perera", TaxType: "Income Tax", BillingPeriod: "2025-Q4", Amount: 750.25},
		{RefNo: "FCAU0002", TaxpayerName: "Nimal Fernando", TaxType: "FCAU Application Fee", BillingPeriod: "2026", Amount: 5000.00},
		{RefNo: "FCAU0003", TaxpayerName: "Global Trading Co", TaxType: "FCAU Application Fee", BillingPeriod: "2026", Amount: 7500.00},
		{RefNo: "VAT202601", TaxpayerName: "Lanka Exports Ltd", TaxType: "VAT", BillingPeriod: "2026-Q1", Amount: 132000.00},
		{RefNo: "VAT202602", TaxpayerName: "Ceylon Foods Pvt Ltd", TaxType: "VAT", BillingPeriod: "2026-Q2", Amount: 98500.75},
		{RefNo: "INC202601", TaxpayerName: "Kamala Wijesinghe", TaxType: "Income Tax", BillingPeriod: "2026-Q1", Amount: 18250.00},
		{RefNo: "INC202602", TaxpayerName: "Ruwan Jayasuriya", TaxType: "Income Tax", BillingPeriod: "2026-Q2", Amount: 9600.00},
		{RefNo: "PAYE0001", TaxpayerName: "Highland Holdings", TaxType: "PAYE", BillingPeriod: "2026-01", Amount: 45000.00},
		{RefNo: "PAYE0002", TaxpayerName: "Summit Apparels", TaxType: "PAYE", BillingPeriod: "2026-02", Amount: 52300.00},
		{RefNo: "NBT202601", TaxpayerName: "Riverside Hotels", TaxType: "Nation Building Tax", BillingPeriod: "2026-Q1", Amount: 27800.50},
		{RefNo: "SD202601", TaxpayerName: "Pearl Distillers", TaxType: "Stamp Duty", BillingPeriod: "2026", Amount: 3200.00},
		{RefNo: "MV202601", TaxpayerName: "Dilshan Rajapaksa", TaxType: "Motor Vehicle Fee", BillingPeriod: "2026", Amount: 12500.00},
		{RefNo: "LIC0001", TaxpayerName: "Coastal Fisheries", TaxType: "License Fee", BillingPeriod: "2026", Amount: 6000.00},
		{RefNo: "LIC0002", TaxpayerName: "Greenfield Agro", TaxType: "License Fee", BillingPeriod: "2026", Amount: 6000.00},
		{RefNo: "CUS202601", TaxpayerName: "Orient Imports", TaxType: "Customs Duty", BillingPeriod: "2026-Q1", Amount: 215000.00},
		{RefNo: "PROP0001", TaxpayerName: "Anoma Senanayake", TaxType: "Property Tax", BillingPeriod: "2026", Amount: 8900.00},
		{RefNo: "PROP0002", TaxpayerName: "Metro Developers", TaxType: "Property Tax", BillingPeriod: "2026", Amount: 156000.00},
	}

	bills := make(map[string]*BillRecord, len(seed))
	for _, b := range seed {
		bills[b.RefNo] = b
	}
	return &BillStore{
		bills: bills,
		paid:  make(map[string]bool),
	}
}

// Lookup returns the bill for refNo, or false if no such reference number exists.
func (s *BillStore) Lookup(refNo string) (*BillRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.bills[refNo]
	return rec, ok
}

// IsPaid reports whether refNo has already been paid.
func (s *BillStore) IsPaid(refNo string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.paid[refNo]
}

// MarkPaid records refNo as paid. It returns false if the refNo is unknown or
// was already paid (so callers can reject a double payment), and true if this
// call is the one that transitioned it to paid.
func (s *BillStore) MarkPaid(refNo string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bills[refNo]; !ok {
		return false
	}
	if s.paid[refNo] {
		return false
	}
	s.paid[refNo] = true
	return true
}
