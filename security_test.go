package ipgeolocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestForwardedHeadersRequireTrustedPeer(t *testing.T) {
	proxies, err := parseCIDRs([]string{"10.0.0.0/8", "2001:db8:ffff::/48"})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"X-Forwarded-For", "CF-Connecting-IP"} {
		for _, depth := range []int{0, 1} {
			resolver := ipResolver{trustForwarded: true, headerName: header, depth: depth, trustedProxies: proxies}
			for _, peer := range []string{"203.0.113.42:1234", "[2001:db8:1::42]:1234"} {
				for _, supplied := range []string{"127.0.0.1", "8.8.8.8", "2001:db8:ffff::9"} {
					req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
					req.RemoteAddr = peer
					req.Header.Set(header, supplied)
					if got, want := resolver.clientIP(req), peerIP(req); !got.Equal(want) {
						t.Errorf("header %s, depth %d, peer %s, supplied %s: got %v, want %v", header, depth, peer, supplied, got, want)
					}
				}
			}
		}
	}
}

func TestTrustedPeerKeepsForwardedStrategies(t *testing.T) {
	proxies, err := parseCIDRs([]string{"10.0.0.0/8", "2001:db8:ffff::/48"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer, header, want string
		depth                    int
	}{
		{"chain", "10.0.0.1:1234", "5.5.5.5, 81.2.69.142, 10.0.0.9", "81.2.69.142", 0},
		{"depth", "10.0.0.1:1234", "81.2.69.142, 198.51.100.4", "198.51.100.4", 1},
		{"IPv6", "[2001:db8:ffff::1]:1234", "2001:db8:1::42, 2001:db8:ffff::9", "2001:db8:1::42", 0},
		{"missing", "10.0.0.1:1234", "", "10.0.0.1", 0},
		{"invalid", "10.0.0.1:1234", "not-an-ip", "10.0.0.1", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := ipResolver{trustForwarded: true, headerName: "X-Forwarded-For", depth: tc.depth, trustedProxies: proxies}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Forwarded-For", tc.header)
			if got := resolver.clientIP(req); !got.Equal(net.ParseIP(tc.want)) {
				t.Errorf("got %v, want %s", got, tc.want)
			}
		})
	}
}

func TestUntrustedPeerCannotBypassRulesWithForwardedAddress(t *testing.T) {
	for _, supplied := range []string{"127.0.0.1", "8.8.8.8"} {
		t.Run(supplied, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.TrustForwardedHeader = true
			cfg.TrustedProxies = []string{"10.0.0.0/8"}
			cfg.AllowedIPs = []string{"8.8.8.8/32"}
			cfg.BlockVPN = true
			rec, seen := serve(t, cfg, "2.56.188.34:1234", map[string]string{"X-Forwarded-For": supplied})
			if rec.Code != http.StatusForbidden || seen != nil {
				t.Fatalf("status %d, backend reached %v; want blocked", rec.Code, seen != nil)
			}
		})
	}
}

func TestAPIErrorLogsOmitCredentials(t *testing.T) {
	secret := "audit-key+with spaces/?&"
	for _, kind := range []string{"transport", "TLS", "timeout", "HTTP", "HTTP long", "message", "invalid JSON"} {
		for _, failOpen := range []bool{false, true} {
			t.Run(kind+"/"+map[bool]string{false: "closed", true: "open"}[failOpen], func(t *testing.T) {
				handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					if req.URL.Query().Get("apiKey") != secret {
						t.Error("API key was not sent unchanged to the API")
					}
					switch kind {
					case "timeout":
						time.Sleep(100 * time.Millisecond)
					case "HTTP":
						rw.WriteHeader(http.StatusInternalServerError)
						_, _ = rw.Write([]byte("API failure: " + secret + " " + url.QueryEscape(secret)))
					case "HTTP long":
						rw.WriteHeader(http.StatusInternalServerError)
						_, _ = rw.Write([]byte(strings.Repeat("x", 190) + secret))
					case "message":
						_ = json.NewEncoder(rw).Encode(map[string]string{"message": "API failure: " + secret})
					default:
						_, _ = rw.Write([]byte("not JSON"))
					}
				})
				var server *httptest.Server
				if kind == "TLS" {
					server = httptest.NewTLSServer(handler)
				} else {
					server = httptest.NewServer(handler)
				}
				t.Cleanup(server.Close)
				if kind == "transport" {
					server.Close()
				}
				cfg := CreateConfig()
				cfg.Mode, cfg.APIKey, cfg.APIEndpoint = modeAPI, secret, server.URL
				cfg.FailOpen, cfg.LogLevel = failOpen, "error"
				if kind == "timeout" {
					cfg.APITimeout = "20ms"
				}
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				backendHit := false
				middleware, err := New(ctx, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
					backendHit = true
					rw.WriteHeader(http.StatusOK)
				}), cfg, "audit")
				if err != nil {
					t.Fatal(err)
				}
				plugin := middleware.(*Plugin)
				var output bytes.Buffer
				plugin.log.out = log.New(&output, "", 0)
				req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
				req.RemoteAddr = "81.2.69.142:1234"
				rec := httptest.NewRecorder()
				plugin.ServeHTTP(rec, req)
				want := http.StatusForbidden
				if failOpen {
					want = http.StatusOK
				}
				if rec.Code != want || backendHit != failOpen {
					t.Errorf("status %d, backend reached %v; want %d/%v", rec.Code, backendHit, want, failOpen)
				}
				message := output.String()
				if !strings.Contains(message, "lookup of 81.2.69.142 failed") {
					t.Errorf("lookup failure was not logged: %s", message)
				}
				for _, value := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
					if strings.Contains(message, value) {
						t.Error("API key appeared in logs")
					}
				}
				if kind == "HTTP long" && strings.Contains(message, "audit-key") {
					t.Error("truncated API key appeared in logs")
				}
			})
		}
	}
}

func TestAPIRedactedErrorPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider, err := newAPIProvider("http://127.0.0.1:1/ipgeo", "audit-key", "", "", time.Second, formatter{}, newLogger("error", "audit"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = provider.lookup(ctx, net.ParseIP("81.2.69.142"), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error no longer wraps cancellation: %v", err)
	}
	var requestError *url.Error
	if !errors.As(err, &requestError) {
		t.Fatalf("error no longer wraps the request failure: %v", err)
	}
	if strings.Contains(err.Error(), "audit-key") {
		t.Error("API key appeared in the error")
	}
}
