package ipgeolocation

import (
	"fmt"
	"strings"
)

// decision is the outcome of evaluating the rules for one request.
type decision struct {
	allowed bool
	reason  string
}

var allowDecision = decision{allowed: true}

// securityRule ties a configuration flag to the field it tests. When unless
// is set, a true value there spares the request: it is how blockBot avoids
// blocking search engine crawlers that the Security v4 database flags as
// known good bots.
type securityRule struct {
	enabled bool
	field   string
	unless  string
	reason  string
}

// ruleSet holds the compiled access rules. Compiling once in New keeps the
// request path free of string splitting and map building.
type ruleSet struct {
	allowedCountries  map[string]bool
	blockedCountries  map[string]bool
	allowedContinents map[string]bool
	blockedContinents map[string]bool
	allowedASNs       map[string]bool
	blockedASNs       map[string]bool

	securityRules []securityRule

	threatScoreAbove int
	allowUnknown     bool
}

func newRuleSet(cfg *Config) (*ruleSet, error) {
	rs := &ruleSet{
		allowedCountries:  upperSet(cfg.AllowedCountries),
		blockedCountries:  upperSet(cfg.BlockedCountries),
		allowedContinents: upperSet(cfg.AllowedContinents),
		blockedContinents: upperSet(cfg.BlockedContinents),
		allowedASNs:       asnSet(cfg.AllowedASNs),
		blockedASNs:       asnSet(cfg.BlockedASNs),
		threatScoreAbove:  cfg.BlockThreatScoreAbove,
		allowUnknown:      cfg.AllowUnknown,
	}

	if len(rs.allowedCountries) > 0 && len(rs.blockedCountries) > 0 {
		return nil, fmt.Errorf("set either allowedCountries or blockedCountries, not both")
	}
	if len(rs.allowedContinents) > 0 && len(rs.blockedContinents) > 0 {
		return nil, fmt.Errorf("set either allowedContinents or blockedContinents, not both")
	}
	if len(rs.allowedASNs) > 0 && len(rs.blockedASNs) > 0 {
		return nil, fmt.Errorf("set either allowedASNs or blockedASNs, not both")
	}
	for code := range rs.allowedCountries {
		if len(code) != 2 {
			return nil, fmt.Errorf("allowedCountries entry %q is not a two letter ISO 3166-1 alpha-2 code", code)
		}
	}
	for code := range rs.blockedCountries {
		if len(code) != 2 {
			return nil, fmt.Errorf("blockedCountries entry %q is not a two letter ISO 3166-1 alpha-2 code", code)
		}
	}

	// Search engine crawlers are flagged as bots and as known good bots.
	// Blocking them delists you, so they are spared unless asked for.
	goodBotGuard := "is_known_good_bot"
	if cfg.BlockKnownGoodBots {
		goodBotGuard = ""
	}

	rs.securityRules = []securityRule{
		{cfg.BlockTor, "is_tor", "", "Tor exit node"},
		{cfg.BlockVPN, "is_vpn", "", "VPN"},
		{cfg.BlockProxy, "is_proxy", "", "proxy"},
		{cfg.BlockRelay, "is_relay", "", "relay"},
		{cfg.BlockResidentialProxy, "is_residential_proxy", "", "residential proxy"},
		{cfg.BlockAnonymous, "is_anonymous", "", "anonymized address"},
		{cfg.BlockKnownAttacker, "is_known_attacker", "", "known attacker"},
		{cfg.BlockBot, "is_bot", goodBotGuard, "known bot"},
		{cfg.BlockSpam, "is_spam", "", "known spam source"},
		{cfg.BlockCloudProvider, "is_cloud_provider", "", "cloud or hosting provider"},
		{cfg.BlockCorporateGateway, "is_corporate_gateway", "", "corporate gateway"},
	}

	return rs, nil
}

// active reports whether any rule would ever block a request.
func (rs *ruleSet) active() bool {
	if len(rs.allowedCountries)+len(rs.blockedCountries) > 0 {
		return true
	}
	if len(rs.allowedContinents)+len(rs.blockedContinents) > 0 {
		return true
	}
	if len(rs.allowedASNs)+len(rs.blockedASNs) > 0 {
		return true
	}
	if rs.threatScoreAbove >= 0 {
		return true
	}
	for _, rule := range rs.securityRules {
		if rule.enabled {
			return true
		}
	}
	return false
}

// requiredFields lists the fields the rules need, so that only those are
// resolved per request.
func (rs *ruleSet) requiredFields() []string {
	out := make([]string, 0, 8)
	if len(rs.allowedCountries)+len(rs.blockedCountries) > 0 {
		out = append(out, "country_code")
	}
	if len(rs.allowedContinents)+len(rs.blockedContinents) > 0 {
		out = append(out, "continent_code")
	}
	if len(rs.allowedASNs)+len(rs.blockedASNs) > 0 {
		out = append(out, "asn")
	}
	if rs.threatScoreAbove >= 0 {
		out = append(out, "threat_score")
	}
	for _, rule := range rs.securityRules {
		if rule.enabled {
			out = append(out, rule.field)
			if rule.unless != "" {
				out = append(out, rule.unless)
			}
		}
	}
	return out
}

// evaluate applies the rules to a resolved set of fields.
func (rs *ruleSet) evaluate(fields map[string]string, found bool) decision {
	if !found {
		if rs.allowUnknown {
			return allowDecision
		}
		return decision{allowed: false, reason: "no geolocation data for this address"}
	}

	country := strings.ToUpper(fields["country_code"])
	if len(rs.allowedCountries) > 0 {
		if country == "" {
			if !rs.allowUnknown {
				return decision{allowed: false, reason: "country is unknown"}
			}
		} else if !rs.allowedCountries[country] {
			return decision{allowed: false, reason: "country " + country + " is not in allowedCountries"}
		}
	}
	if len(rs.blockedCountries) > 0 && country != "" && rs.blockedCountries[country] {
		return decision{allowed: false, reason: "country " + country + " is in blockedCountries"}
	}

	continent := strings.ToUpper(fields["continent_code"])
	if len(rs.allowedContinents) > 0 {
		if continent == "" {
			if !rs.allowUnknown {
				return decision{allowed: false, reason: "continent is unknown"}
			}
		} else if !rs.allowedContinents[continent] {
			return decision{allowed: false, reason: "continent " + continent + " is not in allowedContinents"}
		}
	}
	if len(rs.blockedContinents) > 0 && continent != "" && rs.blockedContinents[continent] {
		return decision{allowed: false, reason: "continent " + continent + " is in blockedContinents"}
	}

	asn := normalizeASN(fields["asn"])
	if len(rs.allowedASNs) > 0 {
		if asn == "" {
			if !rs.allowUnknown {
				return decision{allowed: false, reason: "ASN is unknown"}
			}
		} else if !rs.allowedASNs[asn] {
			return decision{allowed: false, reason: asn + " is not in allowedASNs"}
		}
	}
	if len(rs.blockedASNs) > 0 && asn != "" && rs.blockedASNs[asn] {
		return decision{allowed: false, reason: asn + " is in blockedASNs"}
	}

	for _, rule := range rs.securityRules {
		if !rule.enabled || !truthy(fields[rule.field]) {
			continue
		}
		if rule.unless != "" && truthy(fields[rule.unless]) {
			continue
		}
		return decision{allowed: false, reason: "address is flagged as a " + rule.reason}
	}

	if rs.threatScoreAbove >= 0 {
		if score, ok := numeric(fields["threat_score"]); ok && score > float64(rs.threatScoreAbove) {
			return decision{
				allowed: false,
				reason:  fmt.Sprintf("threat score %s is above %d", fields["threat_score"], rs.threatScoreAbove),
			}
		}
	}

	return allowDecision
}

func upperSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.ToUpper(strings.TrimSpace(part))
			if part != "" {
				out[part] = true
			}
		}
	}
	return out
}

func asnSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if normalized := normalizeASN(part); normalized != "" {
				out[normalized] = true
			}
		}
	}
	return out
}

// normalizeASN accepts "AS1257", "as1257" and "1257" alike.
func normalizeASN(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "AS")
	if value == "" || value == "0" {
		return ""
	}
	return "AS" + value
}
