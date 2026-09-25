package main

import (
	"sort"
	"sync"
)

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
		{RefNo: "PROP0003", TaxpayerName: "Sunil Bandara", TaxType: "Property Tax", BillingPeriod: "2026", Amount: 7400.00},
		{RefNo: "FCAU0004", TaxpayerName: "Blue Ocean Marine", TaxType: "FCAU Application Fee", BillingPeriod: "2026", Amount: 5000.00},
		{RefNo: "FCAU0005", TaxpayerName: "Lanka Spice Traders", TaxType: "FCAU Renewal Fee", BillingPeriod: "2026", Amount: 2500.00},
		{RefNo: "FCAU0006", TaxpayerName: "Serendib Tea Exports", TaxType: "FCAU Renewal Fee", BillingPeriod: "2026", Amount: 2500.00},
		{RefNo: "NPQS0001", TaxpayerName: "Fresh Fields Produce", TaxType: "NPQS Certification Fee", BillingPeriod: "2026", Amount: 4250.00},
		{RefNo: "NPQS0002", TaxpayerName: "Hill Country Nurseries", TaxType: "NPQS Certification Fee", BillingPeriod: "2026", Amount: 4250.00},
		{RefNo: "NPQS0003", TaxpayerName: "Tropicana Fruits Ltd", TaxType: "NPQS Treatment Service Fee", BillingPeriod: "2026", Amount: 11750.00},
		{RefNo: "SLTB0001", TaxpayerName: "Kandy Tea Factory", TaxType: "SLTB Levy Payment", BillingPeriod: "2026-Q1", Amount: 63500.00},
		{RefNo: "SLTB0002", TaxpayerName: "Uva Highlands Estate", TaxType: "SLTB Levy Payment", BillingPeriod: "2026-Q1", Amount: 41200.00},
		{RefNo: "SLTB0003", TaxpayerName: "Ruhuna Tea Brokers", TaxType: "SLTB Lab Test Fee", BillingPeriod: "2026", Amount: 3750.00},
		{RefNo: "CDA0001", TaxpayerName: "Coconut Growers Coop", TaxType: "CDA Application Fee", BillingPeriod: "2026", Amount: 9000.00},
		{RefNo: "CDA0002", TaxpayerName: "Palm Grove Industries", TaxType: "CDA Application Fee", BillingPeriod: "2026", Amount: 9000.00},
		{RefNo: "VAT202603", TaxpayerName: "Metro Retail Chain", TaxType: "VAT", BillingPeriod: "2026-Q3", Amount: 187400.25},
		{RefNo: "VAT202604", TaxpayerName: "Skyline Constructions", TaxType: "VAT", BillingPeriod: "2026-Q3", Amount: 76300.00},
		{RefNo: "VAT202605", TaxpayerName: "Nuwara Beverages", TaxType: "VAT", BillingPeriod: "2026-Q4", Amount: 54900.50},
		{RefNo: "INC202603", TaxpayerName: "Chamari Gunasekara", TaxType: "Income Tax", BillingPeriod: "2026-Q3", Amount: 22150.00},
		{RefNo: "INC202604", TaxpayerName: "Pradeep Silva", TaxType: "Income Tax", BillingPeriod: "2026-Q3", Amount: 4875.75},
		{RefNo: "INC202605", TaxpayerName: "Tharindu Weerasinghe", TaxType: "Income Tax", BillingPeriod: "2026-Q4", Amount: 31600.00},
		{RefNo: "PAYE0003", TaxpayerName: "Orbit Software Pvt Ltd", TaxType: "PAYE", BillingPeriod: "2026-03", Amount: 88450.00},
		{RefNo: "PAYE0004", TaxpayerName: "Lakeview Resorts", TaxType: "PAYE", BillingPeriod: "2026-04", Amount: 37900.00},
		{RefNo: "NBT202602", TaxpayerName: "Galle Fort Traders", TaxType: "Nation Building Tax", BillingPeriod: "2026-Q2", Amount: 19450.00},
		{RefNo: "SD202602", TaxpayerName: "Crown Insurance Ltd", TaxType: "Stamp Duty", BillingPeriod: "2026", Amount: 1850.00},
		{RefNo: "SD202603", TaxpayerName: "Harbour Logistics", TaxType: "Stamp Duty", BillingPeriod: "2026", Amount: 4600.00},
		{RefNo: "MV202602", TaxpayerName: "Nadeeka Herath", TaxType: "Motor Vehicle Fee", BillingPeriod: "2026", Amount: 8750.00},
		{RefNo: "MV202603", TaxpayerName: "Express Transport Co", TaxType: "Motor Vehicle Fee", BillingPeriod: "2026", Amount: 96000.00},
		{RefNo: "LIC0003", TaxpayerName: "Sunrise Poultry Farm", TaxType: "License Fee", BillingPeriod: "2026", Amount: 6000.00},
		{RefNo: "LIC0004", TaxpayerName: "Northern Timber Mills", TaxType: "License Fee", BillingPeriod: "2026", Amount: 15000.00},
		{RefNo: "CUS202602", TaxpayerName: "Pacific Machinery Imports", TaxType: "Customs Duty", BillingPeriod: "2026-Q2", Amount: 342750.00},
		{RefNo: "CUS202603", TaxpayerName: "Silk Route Apparel", TaxType: "Customs Duty", BillingPeriod: "2026-Q3", Amount: 128900.00},
		{RefNo: "TAX2027", TaxpayerName: "Malith Dissanayake", TaxType: "Income Tax", BillingPeriod: "2026-Q4", Amount: 2350.00},
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

// All returns every bill, sorted by refNo, for diagnostics.
func (s *BillStore) All() []*BillRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*BillRecord, 0, len(s.bills))
	for _, b := range s.bills {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RefNo < out[j].RefNo })
	return out
}
