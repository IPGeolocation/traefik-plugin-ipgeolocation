package ipgeolocation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// provider resolves an IP address into a set of formatted fields.
type provider interface {
	// lookup returns the requested fields and whether any data was found.
	lookup(ctx context.Context, ip net.IP, fields []fieldDef) (map[string]string, bool, error)
	describe() string
	close()
}

// extractFields resolves each requested field against the records in order.
// The first record that supplies a non-empty value wins, which is what makes
// layering databases work: load Geolocation plus Security and country fields
// come from the first while the VPN flags come from the second.
func extractFields(records []lookupRecord, fields []fieldDef, f formatter) map[string]string {
	out := make(map[string]string, len(fields))
	for _, def := range fields {
		for _, record := range records {
			if value, ok := f.extract(record, def); ok {
				out[def.name] = value
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// MMDB provider
// ---------------------------------------------------------------------------

// mmdbRecord reads fields for one address out of the database file.
//
// There are two ways to do that, and which is faster depends entirely on how
// many fields the middleware is configured to resolve:
//
//   - Seeking seeks to one path and skips the rest of the record. A location
//     record carries a dozen localized name maps, so skipping them beats
//     decoding them. Each seek re-walks the record, though, so the cost grows
//     with the number of fields.
//   - Decoding materializes the record once and then answers every path from
//     a map, at a fixed cost no matter how many fields follow.
//
// BenchmarkFields* in derived_test.go measures both strategies at three, six,
// nine and fifteen fields. They meet at nine (16.1 vs 16.1 microseconds per
// request); below that seeking wins by a wide margin (3 fields: 6.5 against
// 12.8 microseconds, 91 against 217 allocations) and above it decoding wins
// (15 fields: 20.3 against 27.3). The threshold below is set from that, and
// the provider picks the strategy in New, when the field set is already
// known, so the request path just follows it.
//
// One record is built per address per request and is never shared between
// goroutines, so this needs no locking.
var seekFieldThreshold = 8

type mmdbRecord struct {
	reader   *Reader
	offset   int64
	seekOnly bool
	decoded  interface{}
	failed   bool
}

// newMMDBRecord boxes the record into the interface inside a function call,
// and that detail is load bearing.
//
// Yaegi mis-handles converting a value to an interface inside a loop body:
// appending &mmdbRecord{...} to a []lookupRecord from a range loop leaves
// every element aliased to the last iteration, so a request against three
// layered databases would resolve only the last one's fields. Copying to
// local variables first does not help, nor does building a concrete slice and
// converting it afterwards. Returning the interface from a function does,
// because the conversion then happens in a fresh frame.
//
// Compiled Go behaves correctly either way, so `go test` cannot catch this.
// The Yaegi harness in test/yaegi covers it with layered databases.
func newMMDBRecord(reader *Reader, offset int64, seekOnly bool) lookupRecord {
	return &mmdbRecord{reader: reader, offset: offset, seekOnly: seekOnly}
}

func (m *mmdbRecord) value(path string) (interface{}, bool) {
	if m.failed {
		return nil, false
	}

	if !m.seekOnly {
		if m.decoded == nil {
			record, found, err := m.reader.lookupRecordAt(m.offset)
			if err != nil || !found {
				m.failed = true
				return nil, false
			}
			m.decoded = record
		}
		return resolvePath(m.decoded, path)
	}

	result, found, err := m.reader.Value(m.offset, strings.Split(path, "."))
	if err != nil || !found {
		return nil, false
	}
	return result, true
}

// mmdbProvider answers lookups from one or more local MMDB files. Declaration
// order is priority order.
type mmdbProvider struct {
	mu        sync.RWMutex
	seekOnly  bool
	readers   []*Reader
	paths     []string
	inMemory  bool
	formatter formatter
	log       *logger
	cache     *resultCache
	stop      chan struct{}
	stopOnce  sync.Once
}

func newMMDBProvider(paths []string, inMemory bool, fieldCount int, f formatter, log *logger, cache *resultCache) (*mmdbProvider, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no database files configured")
	}

	readers := make([]*Reader, 0, len(paths))
	for _, path := range paths {
		r, err := OpenReader(path, inMemory)
		if err != nil {
			for _, opened := range readers {
				_ = opened.Close()
			}
			return nil, err
		}
		meta := r.Metadata()
		log.infof("loaded %s (type=%s, records=%d, built=%s, mode=%s)",
			path, meta.DatabaseType, meta.NodeCount, meta.BuildTime().Format("2006-01-02"), memoryModeName(inMemory))
		readers = append(readers, r)
	}

	return &mmdbProvider{
		seekOnly:  fieldCount > 0 && fieldCount <= seekFieldThreshold,
		readers:   readers,
		paths:     paths,
		inMemory:  inMemory,
		formatter: f,
		log:       log,
		cache:     cache,
		stop:      make(chan struct{}),
	}, nil
}

func memoryModeName(inMemory bool) string {
	if inMemory {
		return "memory"
	}
	return "file"
}

func (p *mmdbProvider) lookup(_ context.Context, ip net.IP, fields []fieldDef) (map[string]string, bool, error) {
	p.mu.RLock()
	readers := p.readers
	p.mu.RUnlock()

	records := make([]lookupRecord, 0, len(readers))
	var firstErr error
	for _, r := range readers {
		offset, found, err := r.LookupOffset(ip)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %v", r.Path(), err)
			}
			continue
		}
		if found {
			records = append(records, newMMDBRecord(r, offset, p.seekOnly))
		}
	}

	if len(records) == 0 {
		return map[string]string{}, false, firstErr
	}
	return extractFields(records, fields, p.formatter), true, firstErr
}

func (p *mmdbProvider) describe() string {
	return fmt.Sprintf("mmdb(%s)", strings.Join(p.paths, ", "))
}

func (p *mmdbProvider) close() {
	p.stopOnce.Do(func() { close(p.stop) })
	p.mu.Lock()
	for _, r := range p.readers {
		_ = r.Close()
	}
	p.readers = nil
	p.mu.Unlock()
}

// watch reloads databases whose file on disk has changed. IPGeolocation.io
// publishes fresh releases daily, and the static download links do not
// change, so a cron job that overwrites the files plus this watcher keeps
// Traefik current without a restart.
func (p *mmdbProvider) watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stop:
			return
		case <-ticker.C:
			p.refreshChanged()
		}
	}
}

func (p *mmdbProvider) refreshChanged() {
	p.mu.RLock()
	current := make([]*Reader, len(p.readers))
	copy(current, p.readers)
	p.mu.RUnlock()

	replacements := make(map[int]*Reader)
	for i, r := range current {
		if r == nil || !r.Changed() {
			continue
		}
		fresh, err := OpenReader(r.Path(), p.inMemory)
		if err != nil {
			p.log.warnf("refresh of %s failed, continuing with the loaded database: %v", r.Path(), err)
			continue
		}
		replacements[i] = fresh
	}

	if len(replacements) == 0 {
		return
	}

	p.mu.Lock()
	retired := make([]*Reader, 0, len(replacements))
	for i, fresh := range replacements {
		if i < len(p.readers) {
			retired = append(retired, p.readers[i])
			p.readers[i] = fresh
		}
	}
	p.mu.Unlock()

	p.cache.reset()

	// Give in-flight requests a moment before releasing the old handles.
	go func(old []*Reader) {
		time.Sleep(5 * time.Second)
		for _, r := range old {
			if r != nil {
				_ = r.Close()
			}
		}
	}(retired)

	for i, fresh := range replacements {
		p.log.infof("reloaded database %d: %s (built %s)", i+1, fresh.Path(), fresh.Metadata().BuildTime().Format("2006-01-02"))
	}
}

// ---------------------------------------------------------------------------
// API provider
// ---------------------------------------------------------------------------

// apiProvider answers lookups from the IPGeolocation.io REST API. It is the
// fallback for setups that cannot ship database files; every request that
// misses the cache costs a credit and adds network latency, so MMDB is the
// recommended mode.
type apiProvider struct {
	client    *http.Client
	endpoint  string
	apiKey    string
	include   string
	fieldsArg string
	formatter formatter
	log       *logger
}

func newAPIProvider(endpoint, apiKey, include, fields string, timeout time.Duration, f formatter, log *logger) (*apiProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("apiKey is required when mode is %q", modeAPI)
	}
	if endpoint == "" {
		endpoint = defaultAPIEndpoint
	}
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("invalid apiEndpoint %q: %v", endpoint, err)
	}
	return &apiProvider{
		client:    &http.Client{Timeout: timeout},
		endpoint:  endpoint,
		apiKey:    apiKey,
		include:   include,
		fieldsArg: fields,
		formatter: f,
		log:       log,
	}, nil
}

func (p *apiProvider) lookup(ctx context.Context, ip net.IP, fields []fieldDef) (map[string]string, bool, error) {
	query := url.Values{}
	query.Set("apiKey", p.apiKey)
	query.Set("ip", ip.String())
	if p.include != "" {
		query.Set("include", p.include)
	}
	if p.fieldsArg != "" {
		query.Set("fields", p.fieldsArg)
	}

	separator := "?"
	if strings.Contains(p.endpoint, "?") {
		separator = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+separator+query.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return map[string]string{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, firstLine(string(body)))
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, false, fmt.Errorf("cannot parse the API response: %v", err)
	}
	if message, ok := decoded["message"].(string); ok && len(decoded) == 1 {
		return nil, false, fmt.Errorf("API error: %s", message)
	}

	deriveAPIFlags(decoded)
	return extractFields([]lookupRecord{mapRecord{data: decoded}}, fields, p.formatter), true, nil
}

// deriveAPIFlags fills in flags that the API expresses indirectly, so that
// rules written against the database schema behave the same way in API mode.
func deriveAPIFlags(payload map[string]interface{}) {
	security, ok := payload["security"].(map[string]interface{})
	if !ok {
		return
	}
	proxyType, _ := security["proxy_type"].(string)
	proxyType = strings.ToUpper(strings.TrimSpace(proxyType))
	if proxyType == "" {
		return
	}
	setIfAbsent := func(key string, value bool) {
		if _, exists := security[key]; !exists {
			security[key] = value
		}
	}
	switch proxyType {
	case "VPN":
		setIfAbsent("is_vpn", true)
	case "TOR":
		setIfAbsent("is_tor", true)
	case "RESIDENTIAL":
		setIfAbsent("is_residential_proxy", true)
	case "RELAY":
		setIfAbsent("is_relay", true)
	}
}

func (p *apiProvider) describe() string { return "api(" + p.endpoint + ")" }

func (p *apiProvider) close() {}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
