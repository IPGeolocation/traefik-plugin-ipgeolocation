package ipgeolocation

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// asRecords wraps decoded maps as lookup records.
func asRecords(values ...interface{}) []lookupRecord {
	out := make([]lookupRecord, 0, len(values))
	for _, v := range values {
		out = append(out, mapRecord{data: v})
	}
	return out
}

func writeFile(path string, content []byte) error {
	return os.WriteFile(path, content, 0o644)
}

// geoRecord mirrors the shape of a db-ip-location.mmdb record.
func geoRecord() map[string]interface{} {
	return map[string]interface{}{
		"connection_type": "Cable",
		"time_zone":       "Europe/London",
		"location": map[string]interface{}{
			"accuracy_radius": "6.377",
			"confidence":      "high",
			"dma_code":        "",
			"geoname_id":      "6952659",
			"zipcode":         "GL1",
			"city": map[string]interface{}{
				"name": map[string]interface{}{
					"en": "Gloucester",
					"de": "Gloucester",
					"ru": "Глостер",
				},
			},
			"coordinates": map[string]interface{}{
				"latitude":  "51.86425",
				"longitude": "-2.23816",
			},
			"district": map[string]interface{}{
				"name": map[string]interface{}{"en": "Gloucestershire"},
			},
			"state": map[string]interface{}{
				"code": "GB-ENG",
				"name": map[string]interface{}{"en": "England", "de": "England"},
			},
			"country": map[string]interface{}{
				"code2":    "GB",
				"code3":    "GBR",
				"code_ioc": "GBR",
				"capital":  map[string]interface{}{"en": "London"},
				"continent": map[string]interface{}{
					"code": "EU",
					"name": map[string]interface{}{"en": "Europe", "de": "Europa"},
				},
				"currency": map[string]interface{}{
					"code":   "GBP",
					"name":   map[string]interface{}{"en": "Pound Sterling"},
					"symbol": "£",
				},
				"metadata": map[string]interface{}{
					"calling_code": "+44",
					"languages":    "en-GB,cy-GB,gd",
					"tld":          ".uk",
				},
				"name":          map[string]interface{}{"en": "United Kingdom", "de": "Vereinigtes Königreich"},
				"name_official": map[string]interface{}{"en": "United Kingdom of Great Britain and Northern Ireland"},
			},
		},
	}
}

// securityRecord mirrors the shape of a db-ip-security.mmdb record, including
// the booleans that ship as strings.
func securityRecord() map[string]interface{} {
	return map[string]interface{}{
		"threat_score":           uint64(80),
		"is_tor":                 "false",
		"is_proxy":               "true",
		"is_vpn":                 "true",
		"is_relay":               "false",
		"is_residential_proxy":   "false",
		"is_anonymous":           "true",
		"is_known_attacker":      "true",
		"is_bot":                 "false",
		"is_spam":                "false",
		"is_cloud_provider":      "true",
		"cloud_provider_name":    "Packethub S.A.",
		"proxy_provider_names":   []interface{}{"Zyte Proxy", "Oxy Labs"},
		"vpn_provider_names":     []interface{}{"Nord VPN"},
		"relay_provider_name":    "",
		"proxy_confidence_score": uint64(80),
		"vpn_confidence_score":   uint64(90),
		"proxy_last_seen":        "2026-03-15",
		"vpn_last_seen":          "2026-01-19",
	}
}

func companyRecord() map[string]interface{} {
	return map[string]interface{}{
		"company": map[string]interface{}{
			"name":   map[string]interface{}{"en": "Tele2 Sverige AB"},
			"domain": "tele2.com",
			"type":   "ISP",
		},
	}
}

func asnRecord() map[string]interface{} {
	return map[string]interface{}{
		"asn": map[string]interface{}{
			"as_number":      "1257",
			"as_name":        "TELE2",
			"organization":   "Tele2 Sverige AB",
			"country_code":   "SE",
			"domain":         "tele2.com",
			"type":           "ISP",
			"whois_host":     "RIPE",
			"date_allocated": "2002-09-19",
		},
	}
}

func geoFixture(t *testing.T, recordSize int) []byte {
	t.Helper()
	return buildMMDB(t, recordSize, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
		{network: "2a04:4540::/32", data: geoRecord()},
	})
}

func TestReaderLookupAllRecordSizes(t *testing.T) {
	dir := t.TempDir()

	for _, recordSize := range []int{24, 28, 32} {
		content := geoFixture(t, recordSize)
		path := writeFixture(t, dir, "geo-"+itoa(recordSize)+".mmdb", content)

		for _, inMemory := range []bool{true, false} {
			reader, err := OpenReader(path, inMemory)
			if err != nil {
				t.Fatalf("record size %d, inMemory %v: open failed: %v", recordSize, inMemory, err)
			}

			if got := reader.Metadata().RecordSize; got != uint(recordSize) {
				t.Errorf("record size: got %d, want %d", got, recordSize)
			}
			if got := reader.Metadata().DatabaseType; got != "IPGeolocation-Location" {
				t.Errorf("database type: got %q", got)
			}

			record, found, err := reader.Lookup(net.ParseIP("81.2.69.142"))
			if err != nil || !found {
				t.Fatalf("record size %d, inMemory %v: IPv4 lookup found=%v err=%v", recordSize, inMemory, found, err)
			}
			if value, ok := resolvePath(record, "location.country.code2"); !ok || value != "GB" {
				t.Errorf("country code: got %v (ok=%v)", value, ok)
			}

			if _, found, err = reader.Lookup(net.ParseIP("2a04:4540:1234::1")); err != nil || !found {
				t.Fatalf("record size %d: IPv6 lookup found=%v err=%v", recordSize, found, err)
			}

			if _, found, err = reader.Lookup(net.ParseIP("8.8.8.8")); err != nil {
				t.Fatalf("unexpected error for an absent address: %v", err)
			} else if found {
				t.Errorf("8.8.8.8 should not be in the fixture")
			}

			if err := reader.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}
	}
}

func TestReaderRejectsNonDatabase(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "not-a-database.mmdb", []byte("this is definitely not an MMDB file"))

	if _, err := OpenReader(path, true); err == nil {
		t.Fatal("expected an error for a file without a metadata marker")
	}
	if _, err := OpenReader(dir+"/missing.mmdb", true); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestFieldExtraction(t *testing.T) {
	f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
	known := catalog()
	records := asRecords(geoRecord(), securityRecord(), companyRecord(), asnRecord())

	cases := map[string]string{
		"country_code":      "GB",
		"country_name":      "United Kingdom",
		"continent_code":    "EU",
		"continent_name":    "Europe",
		"city_name":         "Gloucester",
		"district_name":     "Gloucestershire",
		"state_code":        "GB-ENG",
		"state_name":        "England",
		"zip_code":          "GL1",
		"latitude":          "51.86425",
		"time_zone":         "Europe/London",
		"currency_code":     "GBP",
		"currency_name":     "Pound Sterling",
		"calling_code":      "+44",
		"tld":               ".uk",
		"connection_type":   "Cable",
		"threat_score":      "80",
		"is_vpn":            "true",
		"is_tor":            "false",
		"cloud_provider":    "Packethub S.A.",
		"proxy_provider":    "Zyte Proxy,Oxy Labs",
		"vpn_provider":      "Nord VPN",
		"asn":               "AS1257",
		"asn_number":        "1257",
		"asn_organization":  "Tele2 Sverige AB",
		"asn_country":       "SE",
		"asn_rir":           "RIPE",
		"company_name":      "Tele2 Sverige AB",
		"company_domain":    "tele2.com",
		"organization_name": "Tele2 Sverige AB",
	}

	for field, want := range cases {
		def, ok := known[field]
		if !ok {
			t.Fatalf("field %q is missing from the catalog", field)
		}
		got := extractFields(records, []fieldDef{def}, f)[field]
		if got != want {
			t.Errorf("%s: got %q, want %q", field, got, want)
		}
	}
}

func TestFieldExtractionLanguage(t *testing.T) {
	f := formatter{language: "de", listSeparator: ",", trueValue: "true", falseValue: "false"}
	known := catalog()
	records := asRecords(geoRecord())

	if got := extractFields(records, []fieldDef{known["country_name"]}, f)["country_name"]; got != "Vereinigtes Königreich" {
		t.Errorf("German country name: got %q", got)
	}
	// Falls back to English when the requested language is absent.
	if got := extractFields(records, []fieldDef{known["district_name"]}, f)["district_name"]; got != "Gloucestershire" {
		t.Errorf("fallback to English: got %q", got)
	}
}

func TestFieldExtractionBooleanFormat(t *testing.T) {
	f := formatter{language: "en", listSeparator: ",", trueValue: "1", falseValue: "0"}
	known := catalog()
	fields := extractFields(asRecords(securityRecord()), []fieldDef{known["is_vpn"], known["is_tor"]}, f)

	if fields["is_vpn"] != "1" || fields["is_tor"] != "0" {
		t.Errorf("one/zero formatting: got is_vpn=%q is_tor=%q", fields["is_vpn"], fields["is_tor"])
	}
}

func TestLayeredDatabasesFirstMatchWins(t *testing.T) {
	dir := t.TempDir()
	geoPath := writeFixture(t, dir, "geo.mmdb", geoFixture(t, 28))
	secPath := writeFixture(t, dir, "sec.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Security", []dbEntry{
		{network: "81.2.69.0/24", data: securityRecord()},
	}))

	f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
	provider, err := newMMDBProvider([]string{geoPath, secPath}, true, 3, f, newLogger("error", "test"), nil)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	defer provider.close()

	known := catalog()
	fields, found, err := provider.lookup(context.Background(), net.ParseIP("81.2.69.142"),
		[]fieldDef{known["country_code"], known["is_vpn"], known["threat_score"]})
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}

	if fields["country_code"] != "GB" {
		t.Errorf("country came from the wrong database: %q", fields["country_code"])
	}
	if fields["is_vpn"] != "true" || fields["threat_score"] != "80" {
		t.Errorf("security fields not resolved: %#v", fields)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

func timeLater() time.Time {
	return time.Now().Add(2 * time.Second)
}

// TestWriteFixtureDatabase is a development helper: set IPGEO_FIXTURE_OUT to a
// directory and run `go test -run TestWriteFixtureDatabase` to write small
// sample databases you can point the plugin at while evaluating it.
func TestWriteFixtureDatabase(t *testing.T) {
	dir := os.Getenv("IPGEO_FIXTURE_OUT")
	if dir == "" {
		t.Skip("set IPGEO_FIXTURE_OUT to write sample databases")
	}
	writeFixture(t, dir, "db-ip-location.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Location", []dbEntry{
		{network: "81.2.69.0/24", data: geoRecord()},
		{network: "2a04:4540::/32", data: geoRecord()},
	}))
	writeFixture(t, dir, "db-ip-security.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Security", []dbEntry{
		{network: "2.56.188.0/24", data: securityRecord()},
	}))
	writeFixture(t, dir, "db-ip-asn.mmdb", buildMMDB(t, 24, 6, "IPGeolocation-ASN", []dbEntry{
		{network: "81.2.69.0/24", data: asnRecord()},
	}))
}

// TestTargetedAccessMatchesFullDecode compares the seek based reader, which
// the request path uses, against decoding the whole record. Every field in the
// catalog must resolve identically, otherwise the optimization has changed
// behaviour.
func TestTargetedAccessMatchesFullDecode(t *testing.T) {
	dir := t.TempDir()
	merged := map[string]interface{}{}
	for _, part := range []map[string]interface{}{geoRecord(), securityRecord(), companyRecord(), asnRecord()} {
		for k, v := range part {
			merged[k] = v
		}
	}
	path := writeFixture(t, dir, "merged.mmdb", buildMMDB(t, 28, 6, "IPGeolocation-Merged", []dbEntry{
		{network: "81.2.69.0/24", data: merged},
	}))

	for _, inMemory := range []bool{true, false} {
		reader, err := OpenReader(path, inMemory)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		decoded, found, err := reader.Lookup(net.ParseIP("81.2.69.142"))
		if err != nil || !found {
			t.Fatalf("full decode: found=%v err=%v", found, err)
		}
		offset, _, err := reader.LookupOffset(net.ParseIP("81.2.69.142"))
		if err != nil {
			t.Fatalf("offset lookup: %v", err)
		}

		f := formatter{language: "en", listSeparator: ",", trueValue: "true", falseValue: "false"}
		lazy := &mmdbRecord{reader: reader, offset: offset}
		eager := mapRecord{data: decoded}

		checked := 0
		for _, def := range fieldDefs {
			wantValue, wantOK := f.extract(eager, def)
			// A fresh record per field keeps this on the seek path; the
			// shared one above crosses the budget and switches to a full
			// decode, so both code paths get compared.
			fresh := &mmdbRecord{reader: reader, offset: offset}
			freshValue, freshOK := f.extract(fresh, def)
			gotValue, gotOK := f.extract(lazy, def)
			if freshOK != wantOK || freshValue != wantValue {
				t.Errorf("inMemory=%v %s: seek path gave (%q,%v), full decode gave (%q,%v)",
					inMemory, def.name, freshValue, freshOK, wantValue, wantOK)
			}
			if wantOK != gotOK || wantValue != gotValue {
				t.Errorf("inMemory=%v %s: targeted access gave (%q,%v), full decode gave (%q,%v)",
					inMemory, def.name, gotValue, gotOK, wantValue, wantOK)
			}
			if wantOK {
				checked++
			}
		}
		if checked < 25 {
			t.Fatalf("only %d fields resolved, the fixture is not exercising enough of the catalog", checked)
		}
		_ = reader.Close()
	}
}
