package fqdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"
)

const DiagnosticsSocket = "/var/run/aws-node/fqdn.sock"

// ServeDiagnostics is opt-in and root-local. The ordinary metrics endpoint
// intentionally contains no workload identities or DNS names.
func ServeDiagnostics(ctx context.Context, engine *Engine, proxy *Proxy) error {
	if info, err := os.Lstat(DiagnosticsSocket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("FQDN diagnostics path is not a socket")
		}
		conn, dialErr := net.DialTimeout("unix", DiagnosticsSocket, time.Second)
		if dialErr == nil {
			conn.Close()
			return errors.New("FQDN diagnostics socket already has a listener")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return dialErr
		}
		if err := os.Remove(DiagnosticsSocket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", DiagnosticsSocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(DiagnosticsSocket, 0600); err != nil {
		listener.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(struct {
			State Stats
			Proxy ProxyStats
			Ready bool
		}{engine.Stats(), proxy.Stats(), proxy.Ready()})
	})
	mux.HandleFunc("GET /endpoint", func(w http.ResponseWriter, r *http.Request) {
		index, err := strconv.ParseUint(r.URL.Query().Get("ifindex"), 10, 32)
		ip, ipErr := netip.ParseAddr(r.URL.Query().Get("ip"))
		if err != nil || ipErr != nil || index == 0 {
			http.Error(w, "valid ifindex and ip required", http.StatusBadRequest)
			return
		}
		ep, ok := engine.Lookup(uint32(index), ip)
		if !ok {
			http.Error(w, "endpoint not enrolled", http.StatusNotFound)
			return
		}
		diagnostic, err := engine.Inspect(ep)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(diagnostic)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { <-ctx.Done(); server.Close() }()
	go server.Serve(listener)
	return nil
}
