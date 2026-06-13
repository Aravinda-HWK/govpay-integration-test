package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// webDist embeds the built React UI (govpay/web/dist). The directory must exist
// at build time; run `npm run build` in govpay/web first. A .gitkeep keeps it
// present so the build does not fail before the UI is built.
//
//go:embed all:web/dist
var webDist embed.FS

func main() {
	configPath := getEnv("GOVPAY_CONFIG", "config.yaml")
	store, err := LoadStore(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg := store.Snapshot()
	srv := NewServer(store)

	addr := getEnv("GOVPAY_ADDR", cfg.Server.Addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("GovPay+ mock server listening on %s (config=%s, GO=%s, auth=%v)",
		addr, configPath, cfg.GoEndpoint.BaseURL, cfg.GoEndpoint.Auth.Enabled)
	log.Fatal(server.ListenAndServe())
}

// spaHandler serves the embedded React build, falling back to index.html for
// client-side routes (anything that is not a real asset).
func spaHandler() http.Handler {
	dist, err := fs.Sub(webDist, "web/dist")
	if err != nil {
		log.Printf("warning: embedded web/dist unavailable: %v", err)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "UI not built: run `npm run build` in govpay/web", http.StatusNotFound)
		})
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "" {
			clean = "index.html"
		}
		if _, err := fs.Stat(dist, clean); err != nil {
			// Not a real file — serve the SPA entrypoint.
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
