package ipgeolocation

import (
	"sort"
	"strconv"
	"strings"
)

// Field kinds drive formatting and rule comparisons.
const (
	kindString = "string"
	kindBool   = "bool"
	kindNumber = "number"
	kindASN    = "asn"
	kindList   = "list"
)

// fieldDef binds a friendly field name to the candidate paths that may hold
// it. Paths are tried in order, so the current nested IPGeolocation.io schema
// comes first and older or flatter shapes follow. The same catalog serves the
// MMDB databases and the REST API, which is what lets a configuration keep
// working when you switch between them.
type fieldDef struct {
	name  string
	kind  string
	paths []string

	// presence lists paths whose mere presence proves a boolean field true.
	// Some databases are the signal: a record in the Residential Proxy
	// database means the address is a residential proxy, and there is no
	// is_residential_proxy flag to read. These paths are consulted only
	// after every path above has come up empty.
	presence []string
}

var fieldDefs = []fieldDef{
	// Country.
	{"country_code", kindString, []string{"location.country.code2", "country.code2", "location.country_code2", "country_code2", "country_code"}, nil},
	{"country_code3", kindString, []string{"location.country.code3", "country.code3", "location.country_code3", "country_code3"}, nil},
	{"country_code_ioc", kindString, []string{"location.country.code_ioc", "country.code_ioc", "country_code_ioc"}, nil},
	{"country_name", kindString, []string{"location.country.name", "country.name", "location.country_name", "country_name"}, nil},
	{"country_name_official", kindString, []string{"location.country.name_official", "country.name_official", "location.country_name_official", "country_name_official"}, nil},
	{"country_capital", kindString, []string{"location.country.capital", "country.capital", "location.country_capital", "country_capital"}, nil},
	{"is_eu", kindBool, []string{"location.is_eu", "is_eu"}, nil},

	// Continent.
	{"continent_code", kindString, []string{"location.country.continent.code", "country.continent.code", "location.continent_code", "continent_code"}, nil},
	{"continent_name", kindString, []string{"location.country.continent.name", "country.continent.name", "location.continent_name", "continent_name"}, nil},

	// Country metadata.
	{"currency_code", kindString, []string{"location.country.currency.code", "country.currency.code", "currency.code", "currency_code"}, nil},
	{"currency_name", kindString, []string{"location.country.currency.name", "country.currency.name", "currency.name", "currency_name"}, nil},
	{"currency_symbol", kindString, []string{"location.country.currency.symbol", "country.currency.symbol", "currency.symbol", "currency_symbol"}, nil},
	{"calling_code", kindString, []string{"location.country.metadata.calling_code", "country.metadata.calling_code", "country_metadata.calling_code", "calling_code"}, nil},
	{"languages", kindList, []string{"location.country.metadata.languages", "country.metadata.languages", "country_metadata.languages", "languages"}, nil},
	{"tld", kindString, []string{"location.country.metadata.tld", "country.metadata.tld", "country_metadata.tld", "tld"}, nil},

	// Subdivisions and city.
	{"state_code", kindString, []string{"location.state.code", "state.code", "location.state_code", "state_code"}, nil},
	{"state_name", kindString, []string{"location.state.name", "state.name", "location.state_prov", "state_prov", "state_name"}, nil},
	{"district_name", kindString, []string{"location.district.name", "district.name", "location.district", "district", "district_name"}, nil},
	{"city_name", kindString, []string{"location.city.name", "city.name", "location.city", "city", "city_name"}, nil},

	// Position.
	{"zip_code", kindString, []string{"location.zipcode", "location.zip_code", "zipcode", "zip_code", "postal_code"}, nil},
	{"latitude", kindNumber, []string{"location.coordinates.latitude", "location.latitude", "latitude"}, nil},
	{"longitude", kindNumber, []string{"location.coordinates.longitude", "location.longitude", "longitude"}, nil},
	{"geoname_id", kindString, []string{"location.geoname_id", "geoname_id", "geo_name_id"}, nil},
	{"accuracy_radius", kindNumber, []string{"location.accuracy_radius", "accuracy_radius"}, nil},
	{"confidence", kindString, []string{"location.confidence", "confidence"}, nil},
	{"dma_code", kindString, []string{"location.dma_code", "dma_code"}, nil},
	{"time_zone", kindString, []string{"time_zone", "location.time_zone", "time_zone.name", "timezone", "time_zone_name"}, nil},
	{"connection_type", kindString, []string{"connection_type", "location.connection_type"}, nil},

	// Company and ISP.
	{"company_name", kindString, []string{"company.name", "network.company.name", "company_name", "isp"}, nil},
	{"company_domain", kindString, []string{"company.domain", "network.company.domain", "company_domain"}, nil},
	{"company_type", kindString, []string{"company.type", "network.company.type", "company_type"}, nil},
	{"isp_name", kindString, []string{"company.name", "network.company.name", "isp", "company_name"}, nil},
	{"organization_name", kindString, []string{"company.name", "network.company.name", "asn.organization", "network.asn.organization", "organization"}, nil},

	// ASN.
	{"asn", kindASN, []string{"asn.as_number", "network.asn.as_number", "asn.asn", "as_number", "asn"}, nil},
	{"asn_number", kindNumber, []string{"asn.as_number", "network.asn.as_number", "as_number"}, nil},
	{"asn_name", kindString, []string{"asn.as_name", "network.asn.as_name", "as_name"}, nil},
	{"asn_organization", kindString, []string{"asn.organization", "network.asn.organization", "organization"}, nil},
	{"asn_country", kindString, []string{"asn.country_code", "asn.country", "network.asn.country", "asn_country"}, nil},
	{"asn_domain", kindString, []string{"asn.domain", "network.asn.domain"}, nil},
	{"asn_type", kindString, []string{"asn.type", "network.asn.type"}, nil},
	{"asn_rir", kindString, []string{"asn.rir", "asn.whois_host", "network.asn.rir"}, nil},
	{"asn_date_allocated", kindString, []string{"asn.date_allocated", "network.asn.date_allocated"}, nil},
	{"asn_allocation_status", kindString, []string{"asn.allocation_status", "network.asn.allocation_status"}, nil},
	{"asn_routes", kindList, []string{"asn.routes", "network.asn.routes"}, nil},
	{"asn_peers", kindList, []string{"asn.peers", "network.asn.peers"}, nil},
	{"asn_upstreams", kindList, []string{"asn.upstreams", "network.asn.upstreams"}, nil},
	{"asn_downstreams", kindList, []string{"asn.downstreams", "network.asn.downstreams"}, nil},

	// Security and threat intelligence.
	{"threat_score", kindNumber, []string{"threat_score", "security.threat_score"}, nil},
	{"is_tor", kindBool, []string{"is_tor", "security.is_tor"}, nil},
	{"is_proxy", kindBool, []string{"is_proxy", "security.is_proxy"}, nil},
	{"is_vpn", kindBool, []string{"is_vpn", "security.is_vpn"}, nil},
	{"is_relay", kindBool, []string{"is_relay", "security.is_relay"}, nil},
	{"is_residential_proxy", kindBool, []string{"is_residential_proxy", "security.is_residential_proxy"},
		[]string{"proxy_provider", "residential_proxy.provider_name", "residential_proxy_provider_name"}},
	{"is_anonymous", kindBool, []string{"is_anonymous", "security.is_anonymous"}, nil},
	{"is_known_attacker", kindBool, []string{"is_known_attacker", "security.is_known_attacker"}, nil},
	{"is_bot", kindBool, []string{"is_bot", "security.is_bot"}, nil},
	{"is_spam", kindBool, []string{"is_spam", "security.is_spam"}, nil},
	{"is_cloud_provider", kindBool, []string{"is_cloud_provider", "security.is_cloud_provider"},
		[]string{"hosting_provider", "hosting.provider_name"}},
	{"cloud_provider", kindString, []string{"cloud_provider_name", "security.cloud_provider", "cloud_provider"}, nil},
	{"proxy_type", kindString, []string{"proxy_type", "security.proxy_type"}, nil},
	{"proxy_provider", kindList, []string{"proxy_provider_names", "security.proxy_provider", "proxy_provider"}, nil},
	{"vpn_provider", kindList, []string{"vpn_provider_names", "security.vpn_provider", "vpn_provider"}, nil},
	{"relay_provider", kindString, []string{"relay_provider_name", "security.relay_provider", "relay_provider"}, nil},
	{"proxy_confidence", kindNumber, []string{"proxy_confidence_score", "security.proxy_confidence_score"}, nil},
	{"vpn_confidence", kindNumber, []string{"vpn_confidence_score", "security.vpn_confidence_score"}, nil},
	{"proxy_last_seen", kindString, []string{"proxy_last_seen", "security.proxy_last_seen"}, nil},
	{"vpn_last_seen", kindString, []string{"vpn_last_seen", "security.vpn_last_seen"}, nil},

	// Security v4 additions: bot detail and corporate gateways.
	{"is_known_good_bot", kindBool, []string{"is_known_good_bot", "security.is_known_good_bot"}, nil},
	{"bot_type", kindString, []string{"bot_type", "security.bot_type"}, nil},
	// bot_operator_name is the correct name; current Security v4 releases
	// still ship it as bot_owner_name, so both are tried and the plugin
	// keeps working across that fix without a new version.
	{"bot_operator", kindString, []string{
		"bot_operator_name", "security.bot_operator_name",
		"bot_owner_name", "security.bot_owner_name",
	}, nil},
	{"bot_confidence", kindNumber, []string{"bot_confidence_score", "security.bot_confidence_score"}, nil},
	{"bot_last_seen", kindString, []string{"bot_last_seen", "security.bot_last_seen"}, nil},
	{"is_corporate_gateway", kindBool, []string{"is_corporate_gateway", "security.is_corporate_gateway"}, nil},
	{"corporate_gateway_provider", kindString, []string{"corporate_gateway_provider_name", "security.corporate_gateway_provider_name"}, nil},
	{"corporate_gateway_type", kindString, []string{"corporate_gateway_type", "security.corporate_gateway_type"}, nil},

	// Residential proxy and hosting databases.
	{"residential_proxy_provider", kindString, []string{"residential_proxy.provider_name", "residential_proxy_provider_name", "proxy_provider"}, nil},
	{"residential_proxy_last_seen", kindString, []string{"residential_proxy.last_seen", "residential_proxy_last_seen", "last_seen"}, nil},
	{"hosting_provider", kindString, []string{"hosting_provider", "hosting.provider_name", "hosting.provider", "hosting.name"}, nil},

	// Abuse contact.
	{"abuse_name", kindString, []string{"abuse.name", "abuse_name"}, nil},
	{"abuse_email", kindList, []string{"abuse.emails", "abuse.email", "abuse_email"}, nil},
	{"abuse_phone", kindList, []string{"abuse.phone_numbers", "abuse.phone", "abuse_phone"}, nil},
	{"abuse_address", kindString, []string{"abuse.address", "abuse_address"}, nil},
	{"abuse_country_code", kindString, []string{"abuse.country_code", "abuse.country", "abuse_country"}, nil},
	{"abuse_kind", kindString, []string{"abuse.kind", "abuse_kind"}, nil},
	{"abuse_route", kindString, []string{"abuse.route", "abuse.network", "abuse_route"}, nil},
}

// catalog indexes the field definitions by name.
func catalog() map[string]fieldDef {
	out := make(map[string]fieldDef, len(fieldDefs))
	for _, f := range fieldDefs {
		out[f.name] = f
	}
	return out
}

// fieldNames returns every supported field name, sorted.
func fieldNames() []string {
	out := make([]string, 0, len(fieldDefs))
	for _, f := range fieldDefs {
		out = append(out, f.name)
	}
	sort.Strings(out)
	return out
}

// formatter turns decoded MMDB or JSON values into header-ready strings.
type formatter struct {
	language      string
	listSeparator string
	trueValue     string
	falseValue    string
}

// lookupRecord is one source of values for a single address. A decoded JSON
// body resolves paths through maps; an MMDB record resolves them by seeking
// through the encoded bytes, so untouched fields are never decoded.
type lookupRecord interface {
	value(path string) (interface{}, bool)
}

// mapRecord wraps an already decoded record, such as an API response.
type mapRecord struct {
	data interface{}
}

func (m mapRecord) value(path string) (interface{}, bool) {
	return resolvePath(m.data, path)
}

// resolvePath walks a dot separated path through nested maps.
func resolvePath(record interface{}, path string) (interface{}, bool) {
	current := record
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		value, ok := m[part]
		if !ok {
			return nil, false
		}
		current = value
	}
	if current == nil {
		return nil, false
	}
	return current, true
}

// extract returns the first path in the definition that yields a non-empty
// value in the record.
func (f formatter) extract(record lookupRecord, def fieldDef) (string, bool) {
	for _, path := range def.paths {
		raw, ok := record.value(path)
		if !ok {
			continue
		}
		value := f.format(raw, def.kind)
		if value != "" {
			return value, true
		}
	}

	for _, path := range def.presence {
		if raw, ok := record.value(path); ok {
			if f.format(raw, kindString) != "" {
				return f.trueValue, true
			}
		}
	}

	return "", false
}

// format renders a decoded value as a string.
func (f formatter) format(raw interface{}, kind string) string {
	switch v := raw.(type) {
	case nil:
		return ""

	case string:
		s := strings.TrimSpace(v)
		if kind == kindASN {
			return formatASN(s)
		}
		if kind == kindBool {
			// Some database releases store booleans as strings.
			return f.boolString(s == "true" || s == "1" || s == "yes")
		}
		if kind == kindNumber && strings.HasPrefix(s, "AS") {
			return strings.TrimPrefix(s, "AS")
		}
		return s

	case bool:
		return f.boolString(v)

	case float64:
		return trimFloat(v)

	case uint64:
		s := strconv.FormatUint(v, 10)
		if kind == kindASN {
			return formatASN(s)
		}
		if kind == kindBool {
			return f.boolString(v != 0)
		}
		return s

	case int64:
		s := strconv.FormatInt(v, 10)
		if kind == kindASN {
			return formatASN(s)
		}
		if kind == kindBool {
			return f.boolString(v != 0)
		}
		return s

	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			s := f.format(item, kindString)
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, f.listSeparator)

	case []byte:
		return string(v)

	case map[string]interface{}:
		// Localized names and one-level wrappers such as {"name": ...}.
		for _, key := range []string{f.language, "en", "name"} {
			if key == "" {
				continue
			}
			if inner, ok := v[key]; ok {
				if s := f.format(inner, kind); s != "" {
					return s
				}
			}
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s := f.format(v[k], kind); s != "" {
				return s
			}
		}
		return ""
	}

	return ""
}

func (f formatter) boolString(b bool) string {
	if b {
		return f.trueValue
	}
	return f.falseValue
}

// formatASN normalizes an AS number to the "AS1257" form.
func formatASN(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || s == "AS0" {
		return ""
	}
	if strings.HasPrefix(s, "AS") {
		return s
	}
	return "AS" + s
}

// trimFloat prints a float without a trailing ".0" and without scientific
// notation, which keeps coordinates readable in headers and logs.
func trimFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	return s
}

// truthy interprets a formatted value as a boolean.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// numeric interprets a formatted value as a number.
func numeric(s string) (float64, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "AS"))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// Helpers used while reading database metadata.

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asUint(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n < 0 {
			return 0
		}
		return uint64(n)
	case float64:
		if n < 0 {
			return 0
		}
		return uint64(n)
	}
	return 0
}

func asStringMap(v interface{}) map[string]string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, value := range m {
		out[k] = asString(value)
	}
	return out
}

func asStringSlice(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := asString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}
