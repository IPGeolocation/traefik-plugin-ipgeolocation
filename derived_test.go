package ipgeolocation

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// residentialProxyRecord mirrors db-residential-proxy.mmdb, which has no
// is_residential_proxy flag: a record simply existing is the signal.
func residentialProxyRecord() map[string]interface{} {
	return map[string]interface{}{
		"proxy_provider": "Evomi Proxy",
		"last_seen":      "2026-08-28",
	}
}

// hostingRecord mirrors db-ip-hosting.mmdb.
func hostingRecord() map[string]interface{} {
	return map[string]interface{}{
		"hosting_provider": "Shenzhen Tencent Computer Systems Company Limited",
	}
}

func TestFlaglessDatabasesDeriveTheirFlag(t *testing.T) {
	f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
	known := catalog()

	residential := extractFields(asRecords(residentialProxyRecord()),
		[]fieldDef{known["is_residential_proxy"], known["residential_proxy_provider"], known["residential_proxy_last_seen"]}, f)

	if residential["is_residential_proxy"] != "true" {
		t.Errorf("a record in the residential proxy database must imply the flag, got %q", residential["is_residential_proxy"])
	}
	if residential["residential_proxy_provider"] != "Evomi Proxy" {
		t.Errorf("provider: got %q", residential["residential_proxy_provider"])
	}
	if residential["residential_proxy_last_seen"] != "2026-08-28" {
		t.Errorf("last seen: got %q", residential["residential_proxy_last_seen"])
	}

	hosting := extractFields(asRecords(hostingRecord()),
		[]fieldDef{known["is_cloud_provider"], known["hosting_provider"]}, f)

	if hosting["is_cloud_provider"] != "true" {
		t.Errorf("a record in the hosting database must imply the cloud flag, got %q", hosting["is_cloud_provider"])
	}
	if hosting["hosting_provider"] != "Shenzhen Tencent Computer Systems Company Limited" {
		t.Errorf("hosting provider: got %q", hosting["hosting_provider"])
	}

	// An explicit false in the Security database must still win over the
	// derivation, because that database is declared first.
	layered := extractFields(asRecords(
		map[string]interface{}{"is_residential_proxy": "false"},
		residentialProxyRecord(),
	), []fieldDef{known["is_residential_proxy"]}, f)
	if layered["is_residential_proxy"] != "false" {
		t.Errorf("an explicit flag must take priority over the derivation, got %q", layered["is_residential_proxy"])
	}
}

func TestBlockResidentialProxyWithOnlyThatDatabase(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "db-residential-proxy.mmdb",
		buildMMDB(t, 28, 6, "IPGeolocation-ResidentialProxy", []dbEntry{
			{network: "81.2.69.0/24", data: residentialProxyRecord()},
		}))

	cfg := CreateConfig()
	cfg.Databases = []string{path}
	cfg.BlockResidentialProxy = true
	cfg.LogLevel = "error"

	if rec, _ := serve(t, cfg, "81.2.69.142:1234", nil); rec.Code != http.StatusForbidden {
		t.Errorf("residential proxy: got %d, want 403", rec.Code)
	}
	if rec, _ := serve(t, cfg, "8.8.8.8:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("address outside the database: got %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func benchmarkReader(b *testing.B, inMemory bool) {
	t := &testing.T{}
	dir := b.TempDir()
	content := buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
		{network: "2a04:4540::/32", data: geoRecord()},
	})
	path := dir + "/db.mmdb"
	if err := writeFile(path, content); err != nil {
		b.Fatal(err)
	}

	reader, err := OpenReader(path, inMemory)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	ip := net.ParseIP("81.2.69.142")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, found, err := reader.Lookup(ip); err != nil || !found {
			b.Fatalf("lookup failed: found=%v err=%v", found, err)
		}
	}
}

// BenchmarkLookupInMemory measures a tree walk plus a full record decode with
// the database resident in RAM.
func BenchmarkLookupInMemory(b *testing.B) { benchmarkReader(b, true) }

// BenchmarkLookupFromFile measures the same work when only the search tree is
// resident and records are read through the page cache.
func BenchmarkLookupFromFile(b *testing.B) { benchmarkReader(b, false) }

func benchmarkServeHTTP(b *testing.B, cacheSize int, preset string) {
	t := &testing.T{}
	dir := b.TempDir()
	path := dir + "/db.mmdb"
	if err := writeFile(path, buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
	})); err != nil {
		b.Fatal(err)
	}

	cfg := CreateConfig()
	cfg.Databases = []string{path}
	cfg.HeaderPreset = preset
	cfg.CacheSize = cacheSize
	cfg.LogLevel = "error"

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	handler, err := New(context.Background(), next, cfg, "bench")
	if err != nil {
		b.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "81.2.69.142:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), req.Clone(req.Context()))
	}
}

// BenchmarkMiddlewareCached is the steady state: a repeat visitor served from
// the per-address cache.
func BenchmarkMiddlewareCached(b *testing.B) { benchmarkServeHTTP(b, 10000, presetStandard) }

// The uncached benchmarks are the worst case, one full lookup per request,
// across the three header presets. They are what the seek budget in
// provider.go is tuned against.
func BenchmarkMiddlewareUncachedMinimal(b *testing.B) { benchmarkServeHTTP(b, 0, presetMinimal) }

func BenchmarkMiddlewareUncachedStandard(b *testing.B) { benchmarkServeHTTP(b, 0, presetStandard) }

func BenchmarkMiddlewareUncachedFull(b *testing.B) { benchmarkServeHTTP(b, 0, presetFull) }

// benchmarkFieldCount serves requests with an explicit number of resolved
// fields. It is the measurement behind seekFieldThreshold in provider.go: run
// it with the threshold forced high and low to see where seeking stops paying.
func benchmarkFieldCount(b *testing.B, count int, seek bool) {
	original := seekFieldThreshold
	if seek {
		seekFieldThreshold = 1000
	} else {
		seekFieldThreshold = 0
	}
	defer func() { seekFieldThreshold = original }()

	t := &testing.T{}
	dir := b.TempDir()
	path := dir + "/db.mmdb"
	if err := writeFile(path, buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
	})); err != nil {
		b.Fatal(err)
	}

	candidates := []string{
		"country_code", "city_name", "state_code", "country_name", "time_zone",
		"latitude", "longitude", "zip_code", "continent_code", "currency_code",
		"district_name", "tld", "calling_code", "geoname_id", "connection_type",
	}
	headers := map[string]string{}
	for i := 0; i < count && i < len(candidates); i++ {
		headers["X-F-"+itoa(i)] = candidates[i]
	}

	cfg := CreateConfig()
	cfg.Databases = []string{path}
	cfg.HeaderPreset = presetNone
	cfg.Headers = headers
	cfg.CacheSize = 0
	cfg.LogLevel = "error"

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	handler, err := New(context.Background(), next, cfg, "bench")
	if err != nil {
		b.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "81.2.69.142:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), req.Clone(req.Context()))
	}
}

func BenchmarkFields03Seek(b *testing.B)   { benchmarkFieldCount(b, 3, true) }
func BenchmarkFields03Decode(b *testing.B) { benchmarkFieldCount(b, 3, false) }
func BenchmarkFields06Seek(b *testing.B)   { benchmarkFieldCount(b, 6, true) }
func BenchmarkFields06Decode(b *testing.B) { benchmarkFieldCount(b, 6, false) }
func BenchmarkFields09Seek(b *testing.B)   { benchmarkFieldCount(b, 9, true) }
func BenchmarkFields09Decode(b *testing.B) { benchmarkFieldCount(b, 9, false) }
func BenchmarkFields15Seek(b *testing.B)   { benchmarkFieldCount(b, 15, true) }
func BenchmarkFields15Decode(b *testing.B) { benchmarkFieldCount(b, 15, false) }

// securityV4Record mirrors db-ip-security.mmdb from the Security v4 tier,
// which adds bot detail and corporate gateway fields on top of v3.
func securityV4Record() map[string]interface{} {
	return map[string]interface{}{
		"threat_score":                    uint64(45),
		"is_tor":                          "false",
		"is_proxy":                        "true",
		"is_vpn":                          "false",
		"is_relay":                        "false",
		"is_residential_proxy":            "true",
		"is_anonymous":                    "true",
		"is_known_attacker":               "false",
		"is_spam":                         "false",
		"is_cloud_provider":               "false",
		"cloud_provider_name":             "",
		"proxy_provider_names":            []interface{}{"ProxyScrape", "ByteProxies"},
		"proxy_confidence_score":          uint64(99),
		"proxy_last_seen":                 "2026-09-18",
		"vpn_provider_names":              []interface{}{},
		"vpn_confidence_score":            uint64(0),
		"vpn_last_seen":                   "",
		"relay_provider_name":             "",
		"is_bot":                          "true",
		"is_known_good_bot":               "true",
		"bot_type":                        "SEARCH_ENGINE",
		"bot_owner_name":                  "Google LLC", // the name shipping today
		"bot_confidence_score":            uint64(95),
		"bot_last_seen":                   "2026-09-20",
		"is_corporate_gateway":            "false",
		"corporate_gateway_provider_name": "",
		"corporate_gateway_type":          "",
	}
}

func TestSecurityV4Fields(t *testing.T) {
	f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
	known := catalog()
	names := []string{"is_known_good_bot", "bot_type", "bot_operator", "bot_confidence", "bot_last_seen",
		"is_corporate_gateway", "is_vpn", "is_relay", "proxy_confidence", "vpn_confidence", "proxy_last_seen"}
	defs := make([]fieldDef, 0, len(names))
	for _, n := range names {
		def, ok := known[n]
		if !ok {
			t.Fatalf("field %q is missing from the catalog", n)
		}
		defs = append(defs, def)
	}

	got := extractFields(asRecords(securityV4Record()), defs, f)
	want := map[string]string{
		"is_known_good_bot":    "true",
		"bot_type":             "SEARCH_ENGINE",
		"bot_operator":         "Google LLC",
		"bot_confidence":       "95",
		"bot_last_seen":        "2026-09-20",
		"is_corporate_gateway": "false",
		"is_vpn":               "false",
		"is_relay":             "false",
		"proxy_confidence":     "99",
		"vpn_confidence":       "0",
		"proxy_last_seen":      "2026-09-18",
	}
	for field, expected := range want {
		if got[field] != expected {
			t.Errorf("%s: got %q, want %q", field, got[field], expected)
		}
	}
}

// TestBlockBotSparesKnownGoodBots guards against the worst accident available
// here: turning on blockBot and quietly delisting yourself from search
// engines, because crawlers are flagged as bots too.
func TestBlockBotSparesKnownGoodBots(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "db-ip-security.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Security-v4", []dbEntry{
		{network: "81.2.69.0/24", data: securityV4Record()}, // a known good bot
		{network: "2.56.188.0/24", data: map[string]interface{}{
			"is_bot":            "true",
			"is_known_good_bot": "false",
			"threat_score":      uint64(70),
		}},
	}))

	cfg := CreateConfig()
	cfg.Databases = []string{path}
	cfg.BlockBot = true
	cfg.LogLevel = "error"

	if rec, _ := serve(t, cfg, "81.2.69.142:1", nil); rec.Code != http.StatusOK {
		t.Errorf("a known good bot should pass by default: got %d", rec.Code)
	}
	if rec, _ := serve(t, cfg, "2.56.188.34:1", nil); rec.Code != http.StatusForbidden {
		t.Errorf("an ordinary bot should be blocked: got %d", rec.Code)
	}

	// Opting in blocks both.
	cfg2 := CreateConfig()
	cfg2.Databases = []string{path}
	cfg2.BlockBot = true
	cfg2.BlockKnownGoodBots = true
	cfg2.LogLevel = "error"
	if rec, _ := serve(t, cfg2, "81.2.69.142:1", nil); rec.Code != http.StatusForbidden {
		t.Errorf("blockKnownGoodBots should block crawlers too: got %d", rec.Code)
	}
}

// TestBotOperatorNameAcrossReleases covers both spellings: the corrected
// bot_operator_name and the bot_owner_name that current releases ship. The
// corrected one wins when a record carries both.
func TestBotOperatorNameAcrossReleases(t *testing.T) {
	f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
	def := catalog()["bot_operator"]

	cases := []struct {
		name   string
		record map[string]interface{}
		want   string
	}{
		{"corrected name", map[string]interface{}{"bot_operator_name": "Google LLC"}, "Google LLC"},
		{"name shipping today", map[string]interface{}{"bot_owner_name": "Google LLC"}, "Google LLC"},
		{"both present, corrected wins", map[string]interface{}{
			"bot_operator_name": "Google LLC",
			"bot_owner_name":    "stale value",
		}, "Google LLC"},
		{"nested under security, as the API returns it", map[string]interface{}{
			"security": map[string]interface{}{"bot_operator_name": "Bing"},
		}, "Bing"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractFields(asRecords(tc.record), []fieldDef{def}, f)["bot_operator"]
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBlockCorporateGateway(t *testing.T) {
	dir := t.TempDir()
	record := securityV4Record()
	record["is_corporate_gateway"] = "true"
	record["corporate_gateway_provider_name"] = "Zscaler"
	path := writeFixture(t, dir, "db.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Security-v4", []dbEntry{
		{network: "81.2.69.0/24", data: record},
	}))

	cfg := CreateConfig()
	cfg.Databases = []string{path}
	cfg.LogLevel = "error"
	if rec, _ := serve(t, cfg, "81.2.69.142:1", nil); rec.Code != http.StatusOK {
		t.Errorf("corporate gateways pass unless asked for: got %d", rec.Code)
	}

	cfg.BlockCorporateGateway = true
	if rec, _ := serve(t, cfg, "81.2.69.142:1", nil); rec.Code != http.StatusForbidden {
		t.Errorf("blockCorporateGateway should block: got %d", rec.Code)
	}
}
