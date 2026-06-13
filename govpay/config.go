package main

import (
	"fmt"
	"os"
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
	Enabled      bool   `yaml:"enabled" json:"enabled"`
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
	return &Store{path: path, cfg: cfg}, nil
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

// UpdateEndpoint replaces the goEndpoint settings and persists the whole config
// back to disk.
func (s *Store) UpdateEndpoint(ep GoEndpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.GoEndpoint = ep
	s.cfg.applyDefaults()
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	data, err := yaml.Marshal(&s.cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
