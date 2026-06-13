package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk GovPay+ server configuration (config.yaml).
type Config struct {
	Server          ServerConfig     `yaml:"server"`
	GoEndpoint      GoEndpoint       `yaml:"goEndpoint"`
	SubInstitutions []SubInstitution `yaml:"subInstitutions"`
}

type ServerConfig struct {
	Addr string `yaml:"addr"`
}

// GoEndpoint describes how to reach the Government Organization API and whether
// to authenticate against it.
type GoEndpoint struct {
	BaseURL         string     `yaml:"baseURL" json:"baseURL"`
	PresentmentPath string     `yaml:"presentmentPath" json:"presentmentPath"`
	UpdatePath      string     `yaml:"updatePath" json:"updatePath"`
	TransactionKey  string     `yaml:"transactionKey" json:"transactionKey"`
	Auth            AuthConfig `yaml:"auth" json:"auth"`
}

type AuthConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// TokenURL is the full token endpoint URL. It can live on a different host
	// than the GO base URL (e.g. a separate IdP). If left empty it falls back to
	// baseURL + TokenPath.
	TokenURL     string `yaml:"tokenURL" json:"tokenURL"`
	TokenPath    string `yaml:"tokenPath" json:"tokenPath"`
	ClientID     string `yaml:"clientId" json:"clientId"`
	ClientSecret string `yaml:"clientSecret" json:"clientSecret"`
}

// SubInstitution is a sub-institution (subInstId) assigned by GovPay, offering
// one or more services.
type SubInstitution struct {
	ID       string    `yaml:"id" json:"id"`
	Name     string    `yaml:"name" json:"name"`
	Services []Service `yaml:"services" json:"services"`
}

// Service is one payable service under a sub-institution. Each service collects
// into exactly one account.
type Service struct {
	ID      string  `yaml:"id" json:"id"`
	Name    string  `yaml:"name" json:"name"`
	Account Account `yaml:"account" json:"account"`
}

// ServiceContext is the resolved (subInstId, serviceId, serviceName) used when
// building a presentment/update request to the GO.
type ServiceContext struct {
	SubInstID   string
	ServiceID   string
	ServiceName string
}

type Account struct {
	Number string `yaml:"number" json:"number"`
	Name   string `yaml:"name" json:"name"`
}

// Store wraps the config with a mutex and the path it was loaded from, so the
// GovPay+ UI can read and persist endpoint/auth settings at runtime.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func LoadStore(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	return &Store{path: path, cfg: cfg}, nil
}

// applyEnvOverrides lets the GO endpoint be configured at deploy time via
// environment variables (so URLs/secrets are not baked into config.yaml or the
// Helm values file). Only non-empty variables override the file.
func (c *Config) applyEnvOverrides() {
	setStr := func(env string, dst *string) {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			*dst = v
		}
	}
	setStr("GOVPAY_ADDR", &c.Server.Addr)
	setStr("GOVPAY_GO_BASE_URL", &c.GoEndpoint.BaseURL)
	setStr("GOVPAY_GO_PRESENTMENT_PATH", &c.GoEndpoint.PresentmentPath)
	setStr("GOVPAY_GO_UPDATE_PATH", &c.GoEndpoint.UpdatePath)
	setStr("GOVPAY_GO_TRANSACTION_KEY", &c.GoEndpoint.TransactionKey)
	setStr("GOVPAY_AUTH_TOKEN_URL", &c.GoEndpoint.Auth.TokenURL)
	setStr("GOVPAY_AUTH_TOKEN_PATH", &c.GoEndpoint.Auth.TokenPath)
	setStr("GOVPAY_AUTH_CLIENT_ID", &c.GoEndpoint.Auth.ClientID)
	setStr("GOVPAY_AUTH_CLIENT_SECRET", &c.GoEndpoint.Auth.ClientSecret)
	if v := strings.TrimSpace(os.Getenv("GOVPAY_AUTH_ENABLED")); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			c.GoEndpoint.Auth.Enabled = enabled
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Server.Addr == "" {
		c.Server.Addr = ":9091"
	}
	if c.GoEndpoint.PresentmentPath == "" {
		c.GoEndpoint.PresentmentPath = "/api/v1/payments/govpay/validate"
	}
	if c.GoEndpoint.UpdatePath == "" {
		c.GoEndpoint.UpdatePath = "/api/v1/payments/govpay/webhook"
	}
	if c.GoEndpoint.Auth.TokenPath == "" {
		c.GoEndpoint.Auth.TokenPath = "/api/govpayplus/v1.0/generatetoken"
	}
}

// Snapshot returns a copy of the current config for safe concurrent reads.
func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.SubInstitutions = append([]SubInstitution(nil), s.cfg.SubInstitutions...)
	return cfg
}

// FindService resolves a (subInstId, serviceId) pair to its sub-institution and
// service definition.
func (s *Store) FindService(subInstID, serviceID string) (SubInstitution, Service, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.cfg.SubInstitutions {
		if sub.ID != subInstID {
			continue
		}
		for _, svc := range sub.Services {
			if svc.ID == serviceID {
				return sub, svc, true
			}
		}
	}
	return SubInstitution{}, Service{}, false
}

// UpdateEndpoint replaces the goEndpoint settings (in memory) and persists the
// whole config back to disk on a best-effort basis. Persistence is best-effort
// because in a container the config file lives on a read-only image layer; the
// in-memory change still takes effect for the running process.
func (s *Store) UpdateEndpoint(ep GoEndpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.GoEndpoint = ep
	s.cfg.applyDefaults()
	s.persistLocked()
	return nil
}

func (s *Store) persistLocked() {
	data, err := yaml.Marshal(&s.cfg)
	if err != nil {
		log.Printf("warning: could not marshal config for persistence: %v", err)
		return
	}
	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		log.Printf("warning: could not persist config to %s (changes kept in memory): %v", s.path, err)
	}
}
