package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func main() {
	log.Fatal(run(":8080"))
}

// run starts the HTTP server on addr with all routes registered.
func run(addr string) error {
	return http.ListenAndServe(addr, newMux())
}

// newMux builds the HTTP handler with all routes registered.
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	return mux
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
