package ipgeolocation

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// fixtureDatabases writes a geolocation, security and ASN database and
// returns their paths in priority order.
func fixtureDatabases(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()

	geo := buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
		{network: "2a04:4540::/32", data: geoRecord()},
	})
	security := buildMMDB(t, 28, 6, "IPGeolocation-Security", []dbEntry{
		{network: "2.56.188.0/24", data: securityRecord()},
	})
	asn := buildMMDB(t, 24, 6, "IPGeolocation-ASN", []dbEntry{
		{network: "81.2.69.0/24", data: asnRecord()},
	})

	return []string{
		writeFixture(t, dir, "db-ip-location.mmdb", geo),
		writeFixture(t, dir, "db-ip-security.mmdb", security),
		writeFixture(t, dir, "db-ip-asn.mmdb", asn),
	}
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	cfg := CreateConfig()
	cfg.Databases = fixtureDatabases(t)
	cfg.LogLevel = "error"
	return cfg
}

// serve runs one request through the middleware and returns the recorder plus
// the request the backend saw.
func serve(t *testing.T, cfg *Config, remoteAddr string, headers map[string]string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	var seen *http.Request
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seen = req
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("backend"))
	})

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = remoteAddr
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, seen
}

func TestEnrichmentHeaders(t *testing.T) {
	cfg := testConfig(t)
	cfg.HeaderPreset = presetStandard
	cfg.Headers = map[string]string{
		"X-Country":   "country_code",
		"X-Real-Geo":  "city_name",
		"X-IPGeo-ASN": "", // removes a preset header
	}

	rec, seen := serve(t, cfg, "81.2.69.142:5555", map[string]string{
		// A client trying to fake its country must not be believed.
		"X-IPGeo-Country-Code": "US",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if seen == nil {
		t.Fatal("the request never reached the backend")
	}

	checks := map[string]string{
		"X-IPGeo-Country-Code": "GB",
		"X-IPGeo-Country-Name": "United Kingdom",
		"X-IPGeo-City-Name":    "Gloucester",
		"X-IPGeo-State-Code":   "GB-ENG",
		"X-IPGeo-Time-Zone":    "Europe/London",
		"X-IPGeo-Latitude":     "51.86425",
		"X-Country":            "GB",
		"X-Real-Geo":           "Gloucester",
	}
	for header, want := range checks {
		if got := seen.Header.Get(header); got != want {
			t.Errorf("%s: got %q, want %q", header, got, want)
		}
	}
	if got := seen.Header.Get("X-IPGeo-ASN"); got != "" {
		t.Errorf("X-IPGeo-ASN should have been removed by the empty mapping, got %q", got)
	}
}

func TestBlockedCountry(t *testing.T) {
	cfg := testConfig(t)
	cfg.BlockedCountries = []string{"gb", "FR"}
	cfg.BlockMessage = "Not available in your region."

	rec, seen := serve(t, cfg, "81.2.69.142:1234", nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	if seen != nil {
		t.Error("a blocked request must not reach the backend")
	}
	if !strings.Contains(rec.Body.String(), "Not available") {
		t.Errorf("body: got %q", rec.Body.String())
	}
}

func TestAllowedCountriesWhitelist(t *testing.T) {
	cfg := testConfig(t)
	cfg.AllowedCountries = []string{"US", "CA"}
	cfg.BlockStatusCode = http.StatusUnavailableForLegalReasons

	rec, _ := serve(t, cfg, "81.2.69.142:1234", nil)
	if rec.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status: got %d, want 451", rec.Code)
	}

	cfg2 := testConfig(t)
	cfg2.AllowedCountries = []string{"GB"}
	rec2, seen := serve(t, cfg2, "81.2.69.142:1234", nil)
	if rec2.Code != http.StatusOK || seen == nil {
		t.Fatalf("an allowed country was blocked: status %d", rec2.Code)
	}
}

func TestSecurityRules(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Config)
		want  int
	}{
		{"vpn", func(c *Config) { c.BlockVPN = true }, http.StatusForbidden},
		{"tor", func(c *Config) { c.BlockTor = true }, http.StatusOK},
		{"attacker", func(c *Config) { c.BlockKnownAttacker = true }, http.StatusForbidden},
		{"cloud", func(c *Config) { c.BlockCloudProvider = true }, http.StatusForbidden},
		{"threat score above 90", func(c *Config) { c.BlockThreatScoreAbove = 90 }, http.StatusOK},
		{"threat score above 50", func(c *Config) { c.BlockThreatScoreAbove = 50 }, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.setup(cfg)
			rec, _ := serve(t, cfg, "2.56.188.34:9999", nil)
			if rec.Code != tc.want {
				t.Errorf("status: got %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestDryRunDoesNotBlock(t *testing.T) {
	cfg := testConfig(t)
	cfg.BlockedCountries = []string{"GB"}
	cfg.DryRun = true

	rec, seen := serve(t, cfg, "81.2.69.142:1234", nil)
	if rec.Code != http.StatusOK || seen == nil {
		t.Fatalf("dry run blocked the request: status %d", rec.Code)
	}
	if reason := seen.Header.Get("X-IPGeo-Dry-Run"); !strings.Contains(reason, "blockedCountries") {
		t.Errorf("X-IPGeo-Dry-Run: got %q", reason)
	}
}

func TestRedirectInsteadOfBlocking(t *testing.T) {
	cfg := testConfig(t)
	cfg.BlockedCountries = []string{"GB"}
	cfg.BlockRedirectURL = "https://example.org/unavailable"

	rec, _ := serve(t, cfg, "81.2.69.142:1234", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://example.org/unavailable" {
		t.Errorf("Location: got %q", got)
	}
}

func TestPrivateAndBypassAddresses(t *testing.T) {
	cfg := testConfig(t)
	cfg.BlockedCountries = []string{"GB"}
	cfg.AllowedIPs = []string{"203.0.113.0/24"}
	cfg.BlockedIPs = []string{"198.51.100.7"}

	// Private addresses are skipped entirely.
	if rec, _ := serve(t, cfg, "10.1.2.3:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("private address: got %d, want 200", rec.Code)
	}
	// An allowlisted address skips every rule.
	if rec, _ := serve(t, cfg, "203.0.113.9:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("allowlisted address: got %d, want 200", rec.Code)
	}
	// A denylisted address is refused before any lookup.
	if rec, _ := serve(t, cfg, "198.51.100.7:1234", nil); rec.Code != http.StatusForbidden {
		t.Errorf("denylisted address: got %d, want 403", rec.Code)
	}

	cfg2 := testConfig(t)
	cfg2.AllowPrivate = false
	cfg2.AllowUnknown = false
	if rec, _ := serve(t, cfg2, "10.1.2.3:1234", nil); rec.Code != http.StatusForbidden {
		t.Errorf("allowPrivate=false with allowUnknown=false: got %d, want 403", rec.Code)
	}
}

func TestUnknownAddressHandling(t *testing.T) {
	cfg := testConfig(t)
	cfg.AllowUnknown = false
	if rec, _ := serve(t, cfg, "8.8.8.8:1234", nil); rec.Code != http.StatusForbidden {
		t.Errorf("allowUnknown=false: got %d, want 403", rec.Code)
	}

	cfg2 := testConfig(t)
	if rec, _ := serve(t, cfg2, "8.8.8.8:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("allowUnknown=true: got %d, want 200", rec.Code)
	}
}

func TestForwardedHeaderHandling(t *testing.T) {
	// Untrusted by default: the connection address wins.
	cfg := testConfig(t)
	cfg.BlockedCountries = []string{"GB"}
	rec, _ := serve(t, cfg, "8.8.8.8:1234", map[string]string{"X-Forwarded-For": "81.2.69.142"})
	if rec.Code != http.StatusOK {
		t.Errorf("a spoofed X-Forwarded-For was trusted: got %d", rec.Code)
	}

	// Trusted: the header is used.
	cfg2 := testConfig(t)
	cfg2.BlockedCountries = []string{"GB"}
	cfg2.TrustForwardedHeader = true
	rec2, _ := serve(t, cfg2, "8.8.8.8:1234", map[string]string{"X-Forwarded-For": "81.2.69.142, 10.0.0.1"})
	if rec2.Code != http.StatusForbidden {
		t.Errorf("trusted X-Forwarded-For was ignored: got %d", rec2.Code)
	}
}

func TestClientIPResolution(t *testing.T) {
	cases := []struct {
		name     string
		resolver ipResolver
		remote   string
		header   string
		want     string
	}{
		{"peer by default", ipResolver{headerName: "X-Forwarded-For"}, "203.0.113.5:1000", "81.2.69.1", "203.0.113.5"},
		{"leftmost when trusted", ipResolver{trustForwarded: true, headerName: "X-Forwarded-For"}, "10.0.0.1:1000", "81.2.69.1, 10.0.0.2", "81.2.69.1"},
		{"depth one", ipResolver{trustForwarded: true, headerName: "X-Forwarded-For", depth: 1}, "10.0.0.1:1000", "81.2.69.1, 198.51.100.4", "198.51.100.4"},
		{"depth two", ipResolver{trustForwarded: true, headerName: "X-Forwarded-For", depth: 2}, "10.0.0.1:1000", "81.2.69.1, 198.51.100.4", "81.2.69.1"},
		{"ipv6 with port", ipResolver{headerName: "X-Forwarded-For"}, "[2a04:4540::1]:443", "", "2a04:4540::1"},
		{"custom header", ipResolver{trustForwarded: true, headerName: "Cf-Connecting-Ip"}, "10.0.0.1:1000", "81.2.69.9", "81.2.69.9"},
		{"empty header falls back", ipResolver{trustForwarded: true, headerName: "X-Forwarded-For"}, "203.0.113.5:1000", "", "203.0.113.5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tc.remote
			if tc.header != "" {
				req.Header.Set(tc.resolver.headerName, tc.header)
			}
			got := tc.resolver.clientIP(req)
			if got == nil || got.String() != tc.want {
				t.Errorf("got %v, want %s", got, tc.want)
			}
		})
	}
}

func TestTrustedProxiesWalkFromTheRight(t *testing.T) {
	proxies, err := parseCIDRs([]string{"10.0.0.0/8", "192.168.0.0/16"})
	if err != nil {
		t.Fatalf("parseCIDRs: %v", err)
	}
	resolver := ipResolver{trustForwarded: true, headerName: "X-Forwarded-For", trustedProxies: proxies}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:1000"
	req.Header.Set("X-Forwarded-For", "5.5.5.5, 81.2.69.142, 10.0.0.9, 192.168.1.1")

	if got := resolver.clientIP(req); got == nil || got.String() != "81.2.69.142" {
		t.Errorf("got %v, want 81.2.69.142", got)
	}
}

// countingProvider records how many lookups reach the data source.
type countingProvider struct {
	calls  int32
	fields map[string]string
}

func (c *countingProvider) lookup(_ context.Context, _ net.IP, _ []fieldDef) (map[string]string, bool, error) {
	atomic.AddInt32(&c.calls, 1)
	return c.fields, true, nil
}
func (c *countingProvider) describe() string { return "counting" }
func (c *countingProvider) close()           {}

func TestCacheAvoidsRepeatLookups(t *testing.T) {
	cfg := testConfig(t)
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	plugin, ok := handler.(*Plugin)
	if !ok {
		t.Fatal("New did not return *Plugin")
	}

	counter := &countingProvider{fields: map[string]string{"country_code": "GB"}}
	plugin.provider.close()
	plugin.provider = counter

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "81.2.69.142:1234"
		plugin.ServeHTTP(httptest.NewRecorder(), req)
	}

	if got := atomic.LoadInt32(&counter.calls); got != 1 {
		t.Errorf("provider was called %d times, want 1", got)
	}
	if plugin.cache.len() != 1 {
		t.Errorf("cache holds %d entries, want 1", plugin.cache.len())
	}
}

func TestAPIMode(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedQuery = req.URL.RawQuery
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{
			"ip": "2.56.188.34",
			"location": {"country_code2": "SE", "country_name": "Sweden", "city": "Stockholm", "continent_code": "EU"},
			"country_metadata": {"calling_code": "+46", "tld": ".se", "languages": ["sv-SE"]},
			"currency": {"code": "SEK", "name": "Swedish Krona", "symbol": "kr"},
			"asn": {"as_number": "AS1257", "organization": "Tele2 Sverige AB", "country": "SE"},
			"security": {"threat_score": 75, "is_tor": false, "is_proxy": true, "proxy_type": "VPN", "is_known_attacker": true}
		}`))
	}))
	defer server.Close()

	cfg := CreateConfig()
	cfg.Mode = modeAPI
	cfg.APIKey = "test-key"
	cfg.APIEndpoint = server.URL
	cfg.HeaderPreset = presetStandard
	cfg.LogLevel = "error"
	cfg.BlockVPN = true

	rec, seen := serve(t, cfg, "2.56.188.34:4444", nil)

	if !strings.Contains(receivedQuery, "apiKey=test-key") || !strings.Contains(receivedQuery, "ip=2.56.188.34") {
		t.Errorf("query sent to the API: %q", receivedQuery)
	}
	// proxy_type VPN is derived into is_vpn, so the VPN rule fires.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403 (is_vpn derived from proxy_type)", rec.Code)
	}
	if seen != nil {
		t.Error("a blocked request must not reach the backend")
	}

	cfg.BlockVPN = false
	rec2, seen2 := serve(t, cfg, "2.56.188.34:4444", nil)
	if rec2.Code != http.StatusOK || seen2 == nil {
		t.Fatalf("status: got %d, want 200", rec2.Code)
	}
	if got := seen2.Header.Get("X-IPGeo-Country-Code"); got != "SE" {
		t.Errorf("country from the API: got %q, want SE", got)
	}
	if got := seen2.Header.Get("X-IPGeo-Asn"); got != "AS1257" {
		t.Errorf("ASN from the API: got %q, want AS1257", got)
	}
	if got := seen2.Header.Get("X-IPGeo-Threat-Score"); got != "75" {
		t.Errorf("threat score from the API: got %q, want 75", got)
	}
}

func TestAPIFailureRespectsFailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte(`{"message":"boom"}`))
	}))
	defer server.Close()

	cfg := CreateConfig()
	cfg.Mode = modeAPI
	cfg.APIKey = "test-key"
	cfg.APIEndpoint = server.URL
	cfg.LogLevel = "error"

	if rec, _ := serve(t, cfg, "2.56.188.34:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("failOpen=true: got %d, want 200", rec.Code)
	}

	cfg.FailOpen = false
	if rec, _ := serve(t, cfg, "2.56.188.34:1234", nil); rec.Code != http.StatusForbidden {
		t.Errorf("failOpen=false: got %d, want 403", rec.Code)
	}
}

func TestConfigValidation(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	cases := []struct {
		name  string
		build func(*testing.T) *Config
	}{
		{"unknown mode", func(t *testing.T) *Config {
			c := testConfig(t)
			c.Mode = "carrier-pigeon"
			return c
		}},
		{"missing database", func(t *testing.T) *Config {
			c := CreateConfig()
			c.Databases = []string{"/nonexistent/db.mmdb"}
			return c
		}},
		{"no database configured", func(t *testing.T) *Config {
			return CreateConfig()
		}},
		{"api mode without a key", func(t *testing.T) *Config {
			c := CreateConfig()
			c.Mode = modeAPI
			return c
		}},
		{"unknown field in headers", func(t *testing.T) *Config {
			c := testConfig(t)
			c.Headers = map[string]string{"X-Foo": "not_a_field"}
			return c
		}},
		{"allow and block countries together", func(t *testing.T) *Config {
			c := testConfig(t)
			c.AllowedCountries = []string{"US"}
			c.BlockedCountries = []string{"GB"}
			return c
		}},
		{"invalid country code", func(t *testing.T) *Config {
			c := testConfig(t)
			c.BlockedCountries = []string{"GBR"}
			return c
		}},
		{"invalid CIDR", func(t *testing.T) *Config {
			c := testConfig(t)
			c.AllowedIPs = []string{"999.0.0.1/24"}
			return c
		}},
		{"invalid duration", func(t *testing.T) *Config {
			c := testConfig(t)
			c.CacheTTL = "forever"
			return c
		}},
		{"unknown header preset", func(t *testing.T) *Config {
			c := testConfig(t)
			c.HeaderPreset = "everything"
			return c
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(context.Background(), next, tc.build(t), "test"); err == nil {
				t.Error("expected a configuration error, got nil")
			}
		})
	}
}

func TestManifestMatchesPluginContract(t *testing.T) {
	raw, err := os.ReadFile(".traefik.yml")
	if err != nil {
		t.Fatalf("the plugin manifest is required by the Traefik catalog: %v", err)
	}
	manifest := string(raw)

	for _, required := range []string{"displayName:", "type: middleware", "import: github.com/IPGeolocation/traefik-plugin-ipgeolocation", "summary:", "testData:", "basePkg: ipgeolocation"} {
		if !strings.Contains(manifest, required) {
			t.Errorf("the manifest is missing %q", required)
		}
	}

	// The manifest testData must produce a working middleware, because the
	// catalog runs it at import time.
	cfg := CreateConfig()
	cfg.Mode = modeAPI
	cfg.APIKey = "YOUR_API_KEY"
	cfg.HeaderPreset = presetStandard
	cfg.LogLevel = "error"
	if _, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "manifest"); err != nil {
		t.Errorf("the manifest testData does not build a middleware: %v", err)
	}
}

func TestRefreshReloadsChangedDatabase(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "db.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
	}))

	f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
	provider, err := newMMDBProvider([]string{path}, true, 1, f, newLogger("error", "test"), nil)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	defer provider.close()

	known := catalog()
	before, _, _ := provider.lookup(context.Background(), net.ParseIP("81.2.69.142"), []fieldDef{known["country_code"]})
	if before["country_code"] != "GB" {
		t.Fatalf("before refresh: %#v", before)
	}

	// Publish a new release over the same path.
	swapped := geoRecord()
	swapped["location"].(map[string]interface{})["country"].(map[string]interface{})["code2"] = "FR"
	if err := writeFile(path, buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: swapped},
	})); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := os.Chtimes(path, timeLater(), timeLater()); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	provider.refreshChanged()

	after, _, _ := provider.lookup(context.Background(), net.ParseIP("81.2.69.142"), []fieldDef{known["country_code"]})
	if after["country_code"] != "FR" {
		t.Errorf("after refresh: got %q, want FR", after["country_code"])
	}
}
