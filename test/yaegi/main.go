// Command yaegi-check loads the plugin the way Traefik does.
//
// Traefik does not compile plugins, it interprets them with Yaegi, which
// supports a subset of Go. Code that builds and passes `go test` can still
// fail to load in Traefik, so this harness imports the package through Yaegi,
// calls CreateConfig and New by reflection exactly as Traefik's plugin loader
// does, and serves real requests in both MMDB and API mode.
//
// Usage: go run . <plugin-dir> <fixtures-dir>
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

const (
	importPath = "github.com/IPGeolocation/traefik-plugin-ipgeolocation"
	basePkg    = "ipgeolocation"
)

func main() {
	pluginDir, fixturesDir := "../..", "/tmp/ipgeo-fixtures"
	if len(os.Args) > 1 {
		pluginDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		fixturesDir = os.Args[2]
	}

	gopath, err := stagePlugin(pluginDir)
	if err != nil {
		fail("stage plugin sources", err)
	}
	defer func() { _ = os.RemoveAll(gopath) }()

	checker := newChecker(gopath)
	checker.run(fixturesDir)

	fmt.Println("\nAll Yaegi compatibility checks passed.")
}

// stagePlugin copies the plugin's Go files into a GOPATH tree, which is how
// Traefik presents plugins to the interpreter.
func stagePlugin(dir string) (string, error) {
	gopath, err := os.MkdirTemp("", "yaegi-gopath-")
	if err != nil {
		return "", err
	}
	target := filepath.Join(gopath, "src", filepath.FromSlash(importPath))
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	copied := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if err := copyFile(filepath.Join(dir, name), filepath.Join(target, name)); err != nil {
			return "", err
		}
		copied++
	}
	if copied == 0 {
		return "", fmt.Errorf("no Go source files found in %s", dir)
	}
	if err := copyFile(filepath.Join(dir, "go.mod"), filepath.Join(target, "go.mod")); err != nil {
		return "", err
	}
	return gopath, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)
	return err
}

type checker struct {
	interp     *interp.Interpreter
	newFn      reflect.Value
	backendHit bool
	headers    http.Header
}

func newChecker(gopath string) *checker {
	i := interp.New(interp.Options{GoPath: gopath, Env: os.Environ()})
	if err := i.Use(stdlib.Symbols); err != nil {
		fail("load the standard library symbols", err)
	}
	if _, err := i.Eval(fmt.Sprintf("import %q", importPath)); err != nil {
		fail("import the plugin package", err)
	}
	pass("the package imports and type checks under Yaegi")

	newFn, err := i.Eval(basePkg + ".New")
	if err != nil {
		fail("resolve New", err)
	}
	if _, err := i.Eval(basePkg + ".CreateConfig"); err != nil {
		fail("resolve CreateConfig", err)
	}
	pass("CreateConfig and New are exported with the signatures Traefik expects")

	return &checker{interp: i, newFn: newFn}
}

func (c *checker) next() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		c.backendHit = true
		c.headers = req.Header.Clone()
		rw.WriteHeader(http.StatusOK)
	})
}

func (c *checker) build(configure func(reflect.Value)) http.Handler {
	cfg, err := c.interp.Eval(basePkg + ".CreateConfig()")
	if err != nil {
		fail("call CreateConfig", err)
	}
	configure(cfg.Elem())

	results := c.newFn.Call([]reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.ValueOf(c.next()).Convert(reflect.TypeOf((*http.Handler)(nil)).Elem()),
		cfg,
		reflect.ValueOf("yaegi-check"),
	})
	if !results[1].IsNil() {
		fail("call New", results[1].Interface().(error))
	}
	handler, ok := results[0].Interface().(http.Handler)
	if !ok {
		fail("call New", fmt.Errorf("the returned value does not implement http.Handler"))
	}
	return handler
}

func (c *checker) serve(handler http.Handler, remoteAddr string, forwarded ...string) *httptest.ResponseRecorder {
	c.backendHit = false
	c.headers = nil

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = remoteAddr
	if len(forwarded) > 0 {
		req.Header.Set("X-Forwarded-For", forwarded[0])
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func (c *checker) run(fixturesDir string) {
	location := filepath.Join(fixturesDir, "db-ip-location.mmdb")
	security := filepath.Join(fixturesDir, "db-ip-security.mmdb")
	asn := filepath.Join(fixturesDir, "db-ip-asn.mmdb")
	for _, path := range []string{location, security, asn} {
		if _, err := os.Stat(path); err != nil {
			fail("find the sample databases (run `make fixtures` first)", err)
		}
	}

	setString := func(v reflect.Value, field, value string) { v.FieldByName(field).SetString(value) }

	// MMDB mode: lookup, decoding and enrichment.
	enrich := c.build(func(cfg reflect.Value) {
		cfg.FieldByName("Databases").Set(reflect.ValueOf([]string{location, security, asn}))
		setString(cfg, "HeaderPreset", "standard")
		setString(cfg, "LogLevel", "error")
	})
	pass("New builds the middleware in mmdb mode")

	rec := c.serve(enrich, "81.2.69.142:1234")
	if !c.backendHit || rec.Code != http.StatusOK {
		fail("serve an enriched request", fmt.Errorf("status %d, backend reached %v", rec.Code, c.backendHit))
	}
	// These three values come from three different databases, so they also
	// prove that layering works: Yaegi mis-handles interface conversion in a
	// loop, and a regression there silently collapses every record onto the
	// last database. See newMMDBRecord in provider.go.
	for header, want := range map[string]string{
		"X-Ipgeo-Country-Code": "GB",         // db-ip-location
		"X-Ipgeo-City-Name":    "Gloucester", // db-ip-location
		"X-Ipgeo-Asn":          "AS1257",     // db-ip-asn
	} {
		if got := c.headers.Get(header); got != want {
			fail("enrich headers from layered databases", fmt.Errorf("%s: got %q, want %q", header, got, want))
		}
	}
	pass("MMDB lookup, decoding and header enrichment run interpreted")
	pass("three layered databases each contribute their own fields")

	// The minimal preset resolves few enough fields that the provider takes
	// the seek path instead of decoding whole records, so both strategies get
	// exercised.
	seeking := c.build(func(cfg reflect.Value) {
		cfg.FieldByName("Databases").Set(reflect.ValueOf([]string{location, security, asn}))
		setString(cfg, "HeaderPreset", "minimal")
		setString(cfg, "LogLevel", "error")
	})
	if rec := c.serve(seeking, "81.2.69.142:1234"); c.headers.Get("X-Ipgeo-Country-Code") != "GB" ||
		c.headers.Get("X-Ipgeo-Asn") != "AS1257" {
		fail("targeted field access", fmt.Errorf("status %d, headers %v", rec.Code, c.headers))
	}
	pass("targeted (seek based) field access runs interpreted")

	// File backed mode reads records from disk through a window instead of
	// holding the database in memory.
	onDisk := c.build(func(cfg reflect.Value) {
		cfg.FieldByName("Databases").Set(reflect.ValueOf([]string{location, asn}))
		cfg.FieldByName("LoadInMemory").SetBool(false)
		setString(cfg, "HeaderPreset", "standard")
		setString(cfg, "LogLevel", "error")
	})
	if rec := c.serve(onDisk, "81.2.69.142:1234"); c.headers.Get("X-Ipgeo-City-Name") != "Gloucester" {
		fail("file backed mode", fmt.Errorf("status %d, city %q", rec.Code, c.headers.Get("X-Ipgeo-City-Name")))
	}
	pass("file backed mode with windowed reads runs interpreted")

	// IPv6.
	if rec := c.serve(enrich, "[2a04:4540:1234::9]:443"); !c.backendHit || c.headers.Get("X-Ipgeo-Country-Code") != "GB" {
		fail("IPv6 lookup", fmt.Errorf("status %d, country %q", rec.Code, c.headers.Get("X-Ipgeo-Country-Code")))
	}
	pass("IPv6 lookup runs interpreted")

	// Rules.
	blocker := c.build(func(cfg reflect.Value) {
		cfg.FieldByName("Databases").Set(reflect.ValueOf([]string{location, security}))
		cfg.FieldByName("BlockedCountries").Set(reflect.ValueOf([]string{"GB"}))
		cfg.FieldByName("BlockVPN").SetBool(true)
		setString(cfg, "LogLevel", "error")
	})
	if rec := c.serve(blocker, "81.2.69.142:1234"); rec.Code != http.StatusForbidden || c.backendHit {
		fail("country rule", fmt.Errorf("status %d, backend reached %v", rec.Code, c.backendHit))
	}
	if rec := c.serve(blocker, "2.56.188.34:1234"); rec.Code != http.StatusForbidden {
		fail("VPN rule", fmt.Errorf("status %d", rec.Code))
	}
	if rec := c.serve(blocker, "10.0.0.5:1234"); rec.Code != http.StatusOK {
		fail("private address handling", fmt.Errorf("status %d", rec.Code))
	}
	pass("country, VPN and private address rules run interpreted")

	for _, depth := range []int{0, 1} {
		proxy := c.build(func(cfg reflect.Value) {
			cfg.FieldByName("Databases").Set(reflect.ValueOf([]string{location, security}))
			cfg.FieldByName("TrustForwardedHeader").SetBool(true)
			cfg.FieldByName("TrustedProxies").Set(reflect.ValueOf([]string{"10.0.0.0/8"}))
			cfg.FieldByName("ForwardedDepth").SetInt(int64(depth))
			cfg.FieldByName("AllowedIPs").Set(reflect.ValueOf([]string{"8.8.8.8/32"}))
			cfg.FieldByName("BlockVPN").SetBool(true)
			setString(cfg, "HeaderPreset", "standard")
			setString(cfg, "LogLevel", "error")
		})
		for _, supplied := range []string{"127.0.0.1", "8.8.8.8"} {
			if rec := c.serve(proxy, "2.56.188.34:1234", supplied); rec.Code != http.StatusForbidden || c.backendHit {
				fail("untrusted forwarded header", fmt.Errorf("depth %d, status %d, backend reached %v", depth, rec.Code, c.backendHit))
			}
		}
		if rec := c.serve(proxy, "10.0.0.1:1234", "81.2.69.142"); rec.Code != http.StatusOK || c.headers.Get("X-Ipgeo-Country-Code") != "GB" {
			fail("trusted forwarded header", fmt.Errorf("depth %d, status %d, country %q", depth, rec.Code, c.headers.Get("X-Ipgeo-Country-Code")))
		}
	}
	pass("trusted peers supply headers and untrusted peers cannot bypass rules")

	// API mode.
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"ip":"2.56.188.34","location":{"country_code2":"SE","city":"Stockholm"},` +
			`"security":{"threat_score":75,"is_proxy":true,"proxy_type":"VPN"}}`))
	}))
	defer server.Close()

	api := c.build(func(cfg reflect.Value) {
		setString(cfg, "Mode", "api")
		setString(cfg, "APIKey", "key")
		setString(cfg, "APIEndpoint", server.URL)
		setString(cfg, "HeaderPreset", "standard")
		setString(cfg, "LogLevel", "error")
	})
	if rec := c.serve(api, "2.56.188.34:1234"); !c.backendHit || c.headers.Get("X-Ipgeo-Country-Code") != "SE" {
		fail("API mode", fmt.Errorf("status %d, country %q", rec.Code, c.headers.Get("X-Ipgeo-Country-Code")))
	}
	pass("API mode, JSON parsing and flag derivation run interpreted")

	output, err := os.CreateTemp("", "yaegi-api-errors-")
	if err != nil {
		fail("capture API logs", err)
	}
	defer func() { _ = output.Close(); _ = os.Remove(output.Name()) }()
	stdout := c.interp.Symbols("os")["os"]["Stdout"]
	original := reflect.ValueOf(stdout.Interface())
	stdout.Set(reflect.ValueOf(output))
	defer stdout.Set(original)
	const key = "yaegi-key+with spaces/?&"
	errorsAPI := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte(key + " " + url.QueryEscape(key)))
	}))
	closedEndpoint := errorsAPI.URL
	for _, endpoint := range []string{errorsAPI.URL, closedEndpoint} {
		for _, failOpen := range []bool{false, true} {
			failedAPI := c.build(func(cfg reflect.Value) {
				setString(cfg, "Mode", "api")
				setString(cfg, "APIKey", key)
				setString(cfg, "APIEndpoint", endpoint)
				setString(cfg, "LogLevel", "error")
				cfg.FieldByName("FailOpen").SetBool(failOpen)
			})
			rec := c.serve(failedAPI, "81.2.69.142:1234")
			want := http.StatusForbidden
			if failOpen {
				want = http.StatusOK
			}
			if rec.Code != want || c.backendHit != failOpen {
				fail("API failure policy", fmt.Errorf("status %d, backend reached %v", rec.Code, c.backendHit))
			}
		}
		errorsAPI.Close()
	}
	logged, err := os.ReadFile(output.Name())
	if err != nil {
		fail("read API logs", err)
	}
	if !strings.Contains(string(logged), "lookup of") || strings.Contains(string(logged), key) || strings.Contains(string(logged), url.QueryEscape(key)) {
		fail("redact API errors", fmt.Errorf("expected lookup errors without credentials"))
	}
	pass("API errors redact credentials and retain fail-open and fail-closed behavior")
}

func pass(message string) { fmt.Println("PASS  " + message) }

func fail(step string, err error) {
	fmt.Printf("FAIL  %s: %v\n", step, err)
	os.Exit(1)
}
