package ipgeolocation

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Plugin metadata.
const (
	pluginName = "ipgeolocation"
	userAgent  = "traefik-plugin-ipgeolocation/1.0 (+https://ipgeolocation.io)"

	modeMMDB = "mmdb"
	modeAPI  = "api"

	defaultAPIEndpoint = "https://api.ipgeolocation.io/v3/ipgeo"

	presetNone     = "none"
	presetMinimal  = "minimal"
	presetStandard = "standard"
	presetFull     = "full"
)

// Config is the plugin configuration. Every field maps to a camelCase key in
// the Traefik dynamic configuration.
type Config struct {
	// Mode selects the data source: "mmdb" (recommended) reads local
	// IPGeolocation.io database files, "api" calls the REST API.
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty" toml:"mode,omitempty"`

	// Databases lists the .mmdb files to load. Declaration order is
	// priority order: the first database that contains a requested field
	// supplies it, so a Geolocation database and a Security database can be
	// layered.
	Databases []string `json:"databases,omitempty" yaml:"databases,omitempty" toml:"databases,omitempty"`

	// LoadInMemory reads each database fully into RAM. Fastest, but needs
	// as much memory as the files are large. Set it to false for
	// multi-gigabyte databases: the search tree stays resident and records
	// are read from disk through the page cache.
	LoadInMemory bool `json:"loadInMemory,omitempty" yaml:"loadInMemory,omitempty" toml:"loadInMemory,omitempty"`

	// RefreshInterval reloads databases whose file changed on disk, for
	// example after a cron job pulls the daily release. "0" disables it.
	RefreshInterval string `json:"refreshInterval,omitempty" yaml:"refreshInterval,omitempty" toml:"refreshInterval,omitempty"`

	// API mode settings.
	APIKey      string `json:"apiKey,omitempty" yaml:"apiKey,omitempty" toml:"apiKey,omitempty"`
	APIEndpoint string `json:"apiEndpoint,omitempty" yaml:"apiEndpoint,omitempty" toml:"apiEndpoint,omitempty"`
	APIInclude  string `json:"apiInclude,omitempty" yaml:"apiInclude,omitempty" toml:"apiInclude,omitempty"`
	APIFields   string `json:"apiFields,omitempty" yaml:"apiFields,omitempty" toml:"apiFields,omitempty"`
	APITimeout  string `json:"apiTimeout,omitempty" yaml:"apiTimeout,omitempty" toml:"apiTimeout,omitempty"`

	// Client IP selection.
	TrustForwardedHeader bool     `json:"trustForwardedHeader,omitempty" yaml:"trustForwardedHeader,omitempty" toml:"trustForwardedHeader,omitempty"`
	ForwardedHeaderName  string   `json:"forwardedHeaderName,omitempty" yaml:"forwardedHeaderName,omitempty" toml:"forwardedHeaderName,omitempty"`
	ForwardedDepth       int      `json:"forwardedDepth,omitempty" yaml:"forwardedDepth,omitempty" toml:"forwardedDepth,omitempty"`
	TrustedProxies       []string `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty" toml:"trustedProxies,omitempty"`

	// Enrichment.
	HeaderPreset  string            `json:"headerPreset,omitempty" yaml:"headerPreset,omitempty" toml:"headerPreset,omitempty"`
	Headers       map[string]string `json:"headers,omitempty" yaml:"headers,omitempty" toml:"headers,omitempty"`
	Language      string            `json:"language,omitempty" yaml:"language,omitempty" toml:"language,omitempty"`
	ListSeparator string            `json:"listSeparator,omitempty" yaml:"listSeparator,omitempty" toml:"listSeparator,omitempty"`
	BooleanFormat string            `json:"booleanFormat,omitempty" yaml:"booleanFormat,omitempty" toml:"booleanFormat,omitempty"`

	// Access control.
	AllowedIPs            []string `json:"allowedIPs,omitempty" yaml:"allowedIPs,omitempty" toml:"allowedIPs,omitempty"`
	BlockedIPs            []string `json:"blockedIPs,omitempty" yaml:"blockedIPs,omitempty" toml:"blockedIPs,omitempty"`
	AllowPrivate          bool     `json:"allowPrivate,omitempty" yaml:"allowPrivate,omitempty" toml:"allowPrivate,omitempty"`
	AllowUnknown          bool     `json:"allowUnknown,omitempty" yaml:"allowUnknown,omitempty" toml:"allowUnknown,omitempty"`
	AllowedCountries      []string `json:"allowedCountries,omitempty" yaml:"allowedCountries,omitempty" toml:"allowedCountries,omitempty"`
	BlockedCountries      []string `json:"blockedCountries,omitempty" yaml:"blockedCountries,omitempty" toml:"blockedCountries,omitempty"`
	AllowedContinents     []string `json:"allowedContinents,omitempty" yaml:"allowedContinents,omitempty" toml:"allowedContinents,omitempty"`
	BlockedContinents     []string `json:"blockedContinents,omitempty" yaml:"blockedContinents,omitempty" toml:"blockedContinents,omitempty"`
	AllowedASNs           []string `json:"allowedASNs,omitempty" yaml:"allowedASNs,omitempty" toml:"allowedASNs,omitempty"`
	BlockedASNs           []string `json:"blockedASNs,omitempty" yaml:"blockedASNs,omitempty" toml:"blockedASNs,omitempty"`
	BlockTor              bool     `json:"blockTor,omitempty" yaml:"blockTor,omitempty" toml:"blockTor,omitempty"`
	BlockVPN              bool     `json:"blockVPN,omitempty" yaml:"blockVPN,omitempty" toml:"blockVPN,omitempty"`
	BlockProxy            bool     `json:"blockProxy,omitempty" yaml:"blockProxy,omitempty" toml:"blockProxy,omitempty"`
	BlockRelay            bool     `json:"blockRelay,omitempty" yaml:"blockRelay,omitempty" toml:"blockRelay,omitempty"`
	BlockResidentialProxy bool     `json:"blockResidentialProxy,omitempty" yaml:"blockResidentialProxy,omitempty" toml:"blockResidentialProxy,omitempty"`
	BlockAnonymous        bool     `json:"blockAnonymous,omitempty" yaml:"blockAnonymous,omitempty" toml:"blockAnonymous,omitempty"`
	BlockKnownAttacker    bool     `json:"blockKnownAttacker,omitempty" yaml:"blockKnownAttacker,omitempty" toml:"blockKnownAttacker,omitempty"`
	BlockBot              bool     `json:"blockBot,omitempty" yaml:"blockBot,omitempty" toml:"blockBot,omitempty"`
	BlockSpam             bool     `json:"blockSpam,omitempty" yaml:"blockSpam,omitempty" toml:"blockSpam,omitempty"`
	BlockCloudProvider    bool     `json:"blockCloudProvider,omitempty" yaml:"blockCloudProvider,omitempty" toml:"blockCloudProvider,omitempty"`

	// BlockCorporateGateway blocks addresses the Security v4 database
	// identifies as corporate egress gateways. Those carry ordinary
	// employees, so this is rarely what you want.
	BlockCorporateGateway bool `json:"blockCorporateGateway,omitempty" yaml:"blockCorporateGateway,omitempty" toml:"blockCorporateGateway,omitempty"`

	// BlockKnownGoodBots makes blockBot apply to crawlers the Security v4
	// database marks as known good bots, such as search engines. Off by
	// default, because blocking them removes you from search results.
	BlockKnownGoodBots bool `json:"blockKnownGoodBots,omitempty" yaml:"blockKnownGoodBots,omitempty" toml:"blockKnownGoodBots,omitempty"`

	// BlockThreatScoreAbove blocks addresses whose threat score exceeds this
	// value. -1 disables the check.
	BlockThreatScoreAbove int `json:"blockThreatScoreAbove,omitempty" yaml:"blockThreatScoreAbove,omitempty" toml:"blockThreatScoreAbove,omitempty"`

	// DryRun evaluates the rules and logs what would happen without
	// blocking anything. Use it to validate a policy on live traffic.
	DryRun bool `json:"dryRun,omitempty" yaml:"dryRun,omitempty" toml:"dryRun,omitempty"`

	// Block response.
	BlockStatusCode  int    `json:"blockStatusCode,omitempty" yaml:"blockStatusCode,omitempty" toml:"blockStatusCode,omitempty"`
	BlockMessage     string `json:"blockMessage,omitempty" yaml:"blockMessage,omitempty" toml:"blockMessage,omitempty"`
	BlockRedirectURL string `json:"blockRedirectURL,omitempty" yaml:"blockRedirectURL,omitempty" toml:"blockRedirectURL,omitempty"`

	// FailOpen lets requests through when a lookup fails, which is the safe
	// default for availability. Set it to false to fail closed.
	FailOpen bool `json:"failOpen,omitempty" yaml:"failOpen,omitempty" toml:"failOpen,omitempty"`

	// Cache.
	CacheSize int    `json:"cacheSize,omitempty" yaml:"cacheSize,omitempty" toml:"cacheSize,omitempty"`
	CacheTTL  string `json:"cacheTTL,omitempty" yaml:"cacheTTL,omitempty" toml:"cacheTTL,omitempty"`

	// LogLevel is one of error, warn, info or debug.
	LogLevel string `json:"logLevel,omitempty" yaml:"logLevel,omitempty" toml:"logLevel,omitempty"`
}

// CreateConfig returns the default configuration. Traefik calls it before
// decoding the user's settings on top.
func CreateConfig() *Config {
	return &Config{
		Mode:                  modeMMDB,
		LoadInMemory:          true,
		RefreshInterval:       "0",
		APIEndpoint:           defaultAPIEndpoint,
		APIInclude:            "",
		APITimeout:            "2s",
		ForwardedHeaderName:   "X-Forwarded-For",
		HeaderPreset:          presetMinimal,
		Language:              "en",
		ListSeparator:         ",",
		BooleanFormat:         "true_false",
		AllowPrivate:          true,
		AllowUnknown:          true,
		BlockThreatScoreAbove: -1,
		BlockStatusCode:       http.StatusForbidden,
		BlockMessage:          "Access denied.",
		FailOpen:              true,
		CacheSize:             10000,
		CacheTTL:              "1h",
		LogLevel:              "info",
	}
}

// Plugin is the middleware handler.
type Plugin struct {
	next     http.Handler
	name     string
	provider provider
	rules    *ruleSet
	resolver ipResolver
	log      *logger
	cache    *resultCache

	headerMap     map[string]string // header name -> field name
	managed       []string          // header names the plugin owns
	fields        []fieldDef        // fields to resolve per request
	allowedIPs    []*net.IPNet
	blockedIPs    []*net.IPNet
	allowPrivate  bool
	failOpen      bool
	dryRun        bool
	blockStatus   int
	blockMessage  string
	blockRedirect string
}

// New builds the middleware. Traefik calls it once per middleware instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration is missing")
	}
	if next == nil {
		return nil, fmt.Errorf("next handler is missing")
	}

	cfg := withDefaults(config)
	log := newLogger(cfg.LogLevel, name)

	rules, err := newRuleSet(cfg)
	if err != nil {
		return nil, err
	}

	headerMap, err := buildHeaderMap(cfg)
	if err != nil {
		return nil, err
	}

	fields, err := selectFields(headerMap, rules)
	if err != nil {
		return nil, err
	}

	allowedIPs, err := parseCIDRs(cfg.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("allowedIPs: %v", err)
	}
	blockedIPs, err := parseCIDRs(cfg.BlockedIPs)
	if err != nil {
		return nil, fmt.Errorf("blockedIPs: %v", err)
	}
	trustedProxies, err := parseCIDRs(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("trustedProxies: %v", err)
	}

	cacheTTL, err := parseDuration("cacheTTL", cfg.CacheTTL, time.Hour)
	if err != nil {
		return nil, err
	}
	cache := newResultCache(cfg.CacheSize, cacheTTL)

	f := formatter{
		language:      cfg.Language,
		listSeparator: cfg.ListSeparator,
		trueValue:     "true",
		falseValue:    "false",
	}
	if cfg.BooleanFormat == "one_zero" || cfg.BooleanFormat == "1_0" {
		f.trueValue, f.falseValue = "1", "0"
	}

	if cfg.BlockRedirectURL == "" && (cfg.BlockStatusCode < 100 || cfg.BlockStatusCode > 599) {
		return nil, fmt.Errorf("blockStatusCode %d is not a valid HTTP status code", cfg.BlockStatusCode)
	}

	var prov provider
	switch strings.ToLower(cfg.Mode) {
	case modeMMDB:
		mp, err := newMMDBProvider(cfg.Databases, cfg.LoadInMemory, len(fields), f, log, cache)
		if err != nil {
			return nil, fmt.Errorf("mmdb mode: %v", err)
		}
		refresh, err := parseDuration("refreshInterval", cfg.RefreshInterval, 0)
		if err != nil {
			return nil, err
		}
		if refresh > 0 {
			if refresh < time.Minute {
				refresh = time.Minute
			}
			go mp.watch(ctx, refresh)
			log.infof("watching databases for updates every %s", refresh)
		}
		prov = mp

	case modeAPI:
		timeout, err := parseDuration("apiTimeout", cfg.APITimeout, 2*time.Second)
		if err != nil {
			return nil, err
		}
		ap, err := newAPIProvider(cfg.APIEndpoint, cfg.APIKey, cfg.APIInclude, cfg.APIFields, timeout, f, log)
		if err != nil {
			return nil, err
		}
		log.warnf("API mode is enabled: every cache miss costs a lookup credit and adds network latency. " +
			"For production traffic prefer mode \"mmdb\" with local database files.")
		prov = ap

	default:
		return nil, fmt.Errorf("unknown mode %q: use %q or %q", cfg.Mode, modeMMDB, modeAPI)
	}

	p := &Plugin{
		next:          next,
		name:          name,
		provider:      prov,
		rules:         rules,
		log:           log,
		cache:         cache,
		headerMap:     headerMap,
		managed:       managedHeaderNames(headerMap),
		fields:        fields,
		allowedIPs:    allowedIPs,
		blockedIPs:    blockedIPs,
		allowPrivate:  cfg.AllowPrivate,
		failOpen:      cfg.FailOpen,
		dryRun:        cfg.DryRun,
		blockStatus:   cfg.BlockStatusCode,
		blockMessage:  cfg.BlockMessage,
		blockRedirect: cfg.BlockRedirectURL,
		resolver: ipResolver{
			trustForwarded: cfg.TrustForwardedHeader,
			headerName:     cfg.ForwardedHeaderName,
			depth:          cfg.ForwardedDepth,
			trustedProxies: trustedProxies,
		},
	}

	if cfg.DryRun && rules.active() {
		log.infof("dry run is enabled: rules are evaluated and logged but nothing is blocked")
	}
	log.infof("ready with %s, %d header(s), %d field(s) per request", prov.describe(), len(headerMap), len(fields))

	// Release database handles when Traefik tears the middleware down.
	go func() {
		<-ctx.Done()
		prov.close()
	}()

	return p, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := p.resolver.clientIP(req)

	// Strip anything a client may have sent under a header we own.
	p.stripManagedHeaders(req)

	if ip == nil {
		p.log.debugf("could not determine a client IP from %q", req.RemoteAddr)
		p.finish(rw, req, decision{allowed: p.failOpen, reason: "client IP is unknown"})
		return
	}

	if ipInNets(ip, p.allowedIPs) {
		p.log.debugf("%s is in allowedIPs, skipping every check", ip)
		p.next.ServeHTTP(rw, req)
		return
	}
	if ipInNets(ip, p.blockedIPs) {
		p.finish(rw, req, decision{allowed: false, reason: "address is in blockedIPs"})
		return
	}

	if isLocalIP(ip) && p.allowPrivate {
		p.log.debugf("%s is private or loopback, skipping the lookup", ip)
		p.next.ServeHTTP(rw, req)
		return
	}

	fields, found, err := p.resolve(req.Context(), ip)
	if err != nil {
		p.log.errorf("lookup of %s failed: %v", ip, err)
		if len(fields) == 0 {
			p.finish(rw, req, decision{allowed: p.failOpen, reason: "lookup failed"})
			return
		}
	}

	p.applyHeaders(req, ip, fields)

	result := p.rules.evaluate(fields, found)
	if !result.allowed {
		p.log.infof("%s: %s", ip, result.reason)
	}
	p.finish(rw, req, result)
}

// resolve returns the fields for an address, using the cache when possible.
func (p *Plugin) resolve(ctx context.Context, ip net.IP) (map[string]string, bool, error) {
	key := ip.String()
	if entry, ok := p.cache.get(key); ok {
		return entry.fields, entry.found, nil
	}

	fields, found, err := p.provider.lookup(ctx, ip, p.fields)
	if fields == nil {
		fields = map[string]string{}
	}
	if err == nil {
		p.cache.put(key, fields, found)
	}
	return fields, found, err
}

// applyHeaders sets the configured headers on the outgoing request.
func (p *Plugin) applyHeaders(req *http.Request, ip net.IP, fields map[string]string) {
	for header, field := range p.headerMap {
		var value string
		if field == "ip" {
			value = ip.String()
		} else {
			value = fields[field]
		}
		if value != "" {
			req.Header.Set(header, value)
		}
	}
}

func (p *Plugin) stripManagedHeaders(req *http.Request) {
	for _, header := range p.managed {
		req.Header.Del(header)
	}
}

// finish either forwards the request or writes the block response.
func (p *Plugin) finish(rw http.ResponseWriter, req *http.Request, result decision) {
	if result.allowed {
		p.next.ServeHTTP(rw, req)
		return
	}

	if p.dryRun {
		req.Header.Set("X-IPGeo-Dry-Run", result.reason)
		p.next.ServeHTTP(rw, req)
		return
	}

	if p.blockRedirect != "" {
		http.Redirect(rw, req, p.blockRedirect, http.StatusFound)
		return
	}

	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(p.blockStatus)
	if p.blockMessage != "" {
		_, _ = rw.Write([]byte(p.blockMessage + "\n"))
	}
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

func withDefaults(in *Config) *Config {
	cfg := *in
	if strings.TrimSpace(cfg.Mode) == "" {
		if cfg.APIKey != "" && len(cfg.Databases) == 0 {
			cfg.Mode = modeAPI
		} else {
			cfg.Mode = modeMMDB
		}
	}
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = defaultAPIEndpoint
	}
	if cfg.APITimeout == "" {
		cfg.APITimeout = "2s"
	}
	if cfg.ForwardedHeaderName == "" {
		cfg.ForwardedHeaderName = "X-Forwarded-For"
	}
	if cfg.HeaderPreset == "" {
		cfg.HeaderPreset = presetMinimal
	}
	if cfg.Language == "" {
		cfg.Language = "en"
	}
	if cfg.ListSeparator == "" {
		cfg.ListSeparator = ","
	}
	if cfg.BooleanFormat == "" {
		cfg.BooleanFormat = "true_false"
	}
	if cfg.BlockStatusCode == 0 {
		cfg.BlockStatusCode = http.StatusForbidden
	}
	if cfg.CacheTTL == "" {
		cfg.CacheTTL = "1h"
	}
	if cfg.RefreshInterval == "" {
		cfg.RefreshInterval = "0"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.BlockThreatScoreAbove == 0 {
		// Zero means "not set" once the value has travelled through the
		// dynamic configuration, and blocking everything above zero is
		// never what someone means by leaving it out.
		cfg.BlockThreatScoreAbove = -1
	}
	return &cfg
}

// buildHeaderMap combines the preset with any explicit header mapping.
func buildHeaderMap(cfg *Config) (map[string]string, error) {
	out := map[string]string{}
	known := catalog()

	switch strings.ToLower(cfg.HeaderPreset) {
	case presetNone, "":
	case presetMinimal:
		addPresetHeaders(out, []string{"country_code", "city_name", "asn"})
	case presetStandard:
		addPresetHeaders(out, []string{
			"country_code", "country_name", "continent_code", "state_code", "city_name",
			"zip_code", "latitude", "longitude", "time_zone", "asn", "organization_name",
			"threat_score", "is_vpn", "is_proxy", "is_tor",
		})
	case presetFull:
		addPresetHeaders(out, fieldNames())
		out["X-IPGeo-IP"] = "ip"
	default:
		return nil, fmt.Errorf("unknown headerPreset %q: use none, minimal, standard or full", cfg.HeaderPreset)
	}

	for header, field := range cfg.Headers {
		header = strings.TrimSpace(header)
		field = strings.TrimSpace(field)
		if header == "" {
			continue
		}
		if field == "" {
			// An empty value removes a header the preset added.
			delete(out, http.CanonicalHeaderKey(header))
			continue
		}
		if field != "ip" {
			if _, ok := known[field]; !ok {
				return nil, fmt.Errorf("header %q refers to unknown field %q; supported fields: %s",
					header, field, strings.Join(fieldNames(), ", "))
			}
		}
		out[http.CanonicalHeaderKey(header)] = field
	}

	return out, nil
}

func addPresetHeaders(out map[string]string, fields []string) {
	for _, field := range fields {
		out[headerNameForField(field)] = field
	}
}

// headerNameForField turns "country_code" into "X-IPGeo-Country-Code".
func headerNameForField(field string) string {
	parts := strings.Split(field, "_")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return http.CanonicalHeaderKey("X-IPGeo-" + strings.Join(parts, "-"))
}

// selectFields returns the field definitions needed by the headers and rules,
// so a request never resolves more than it has to.
func selectFields(headerMap map[string]string, rules *ruleSet) ([]fieldDef, error) {
	known := catalog()
	wanted := map[string]bool{}

	for _, field := range headerMap {
		if field != "ip" {
			wanted[field] = true
		}
	}
	for _, field := range rules.requiredFields() {
		wanted[field] = true
	}

	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]fieldDef, 0, len(names))
	for _, name := range names {
		def, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown field %q", name)
		}
		out = append(out, def)
	}
	return out, nil
}

func managedHeaderNames(headerMap map[string]string) []string {
	out := make([]string, 0, len(headerMap)+1)
	for header := range headerMap {
		out = append(out, header)
	}
	out = append(out, "X-IPGeo-Dry-Run")
	sort.Strings(out)
	return out
}

func parseDuration(name, value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	if value == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration such as \"30s\", \"5m\" or \"24h\"", name, value)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

const (
	levelError = iota
	levelWarn
	levelInfo
	levelDebug
)

type logger struct {
	level int
	out   *log.Logger
}

func newLogger(level, name string) *logger {
	l := levelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		l = levelError
	case "warn", "warning":
		l = levelWarn
	case "info", "":
		l = levelInfo
	case "debug":
		l = levelDebug
	}
	prefix := fmt.Sprintf("[%s] %s: ", pluginName, name)
	return &logger{level: l, out: log.New(os.Stdout, prefix, log.LstdFlags|log.LUTC)}
}

func (l *logger) errorf(format string, args ...interface{}) {
	l.printf(levelError, "ERROR "+format, args...)
}
func (l *logger) warnf(format string, args ...interface{}) {
	l.printf(levelWarn, "WARN "+format, args...)
}
func (l *logger) infof(format string, args ...interface{}) {
	l.printf(levelInfo, "INFO "+format, args...)
}
func (l *logger) debugf(format string, args ...interface{}) {
	l.printf(levelDebug, "DEBUG "+format, args...)
}

func (l *logger) printf(level int, format string, args ...interface{}) {
	if l == nil || l.out == nil || level > l.level {
		return
	}
	l.out.Printf(format, args...)
}
