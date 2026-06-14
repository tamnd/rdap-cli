package rdap

import (
	"testing"
)

func TestDomainInfo(t *testing.T) {
	info := Domain{}.Info()
	if info.Scheme != "rdap" {
		t.Errorf("Scheme = %q, want rdap", info.Scheme)
	}
	if len(info.Hosts) == 0 {
		t.Error("Hosts is empty")
	}
	if info.Identity.Binary != "rdap" {
		t.Errorf("Identity.Binary = %q, want rdap", info.Identity.Binary)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in  string
		typ string
		id  string
	}{
		{"8.8.8.8", "ip", "8.8.8.8"},
		{"2001:4860:4860::8888", "ip", "2001:4860:4860::8888"},
		{"192.168.0.0/16", "ip", "192.168.0.0/16"},
		{"15169", "asn", "15169"},
		{"AS15169", "asn", "15169"},
		{"as15169", "asn", "15169"},
		{"example.com", "domain", "example.com"},
		{"EXAMPLE.COM", "domain", "example.com"},
		{"google.org", "domain", "google.org"},
	}
	for _, tc := range cases {
		typ, id, err := Domain{}.Classify(tc.in)
		if err != nil {
			t.Errorf("Classify(%q) returned error: %v", tc.in, err)
			continue
		}
		if typ != tc.typ || id != tc.id {
			t.Errorf("Classify(%q) = (%q, %q), want (%q, %q)",
				tc.in, typ, id, tc.typ, tc.id)
		}
	}
}

func TestLocate(t *testing.T) {
	cases := []struct {
		typ  string
		id   string
		want string
	}{
		{"domain", "example.com", "https://lookup.icann.org/en/lookup?name=example.com"},
		{"ip", "8.8.8.8", "https://search.arin.net/rdap/#/results/8.8.8.8"},
		{"asn", "15169", "https://search.arin.net/rdap/#/results/AS15169"},
	}
	for _, tc := range cases {
		got, err := Domain{}.Locate(tc.typ, tc.id)
		if err != nil {
			t.Errorf("Locate(%q, %q) error: %v", tc.typ, tc.id, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Locate(%q, %q) = %q, want %q", tc.typ, tc.id, got, tc.want)
		}
	}
}

func TestLocateUnknownType(t *testing.T) {
	_, err := Domain{}.Locate("unknown", "foo")
	if err == nil {
		t.Error("expected error for unknown type, got nil")
	}
}

func TestDomainURL(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"example.com", BaseURLVerisign + "/domain/EXAMPLE.COM"},
		{"example.net", BaseURLVerisign + "/domain/EXAMPLE.NET"},
		{"example.org", BaseURLPIR + "/domain/example.org"},
		{"example.io", BaseURLARIN + "/domain/example.io"},
	}
	for _, tc := range cases {
		got := domainURL(tc.name)
		if got != tc.want {
			t.Errorf("domainURL(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParseDomain(t *testing.T) {
	data := []byte(`{
		"ldhName": "EXAMPLE.COM",
		"status": ["active"],
		"events": [
			{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
			{"eventAction": "last changed",  "eventDate": "2023-08-13T07:00:00Z"},
			{"eventAction": "expiration",    "eventDate": "2026-08-13T04:00:00Z"}
		],
		"nameservers": [
			{"ldhName": "A.IANA-SERVERS.NET"},
			{"ldhName": "B.IANA-SERVERS.NET"}
		],
		"entities": [
			{
				"roles": ["registrar"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn",      {}, "text", "Test Registrar LLC"]
				]]
			},
			{
				"roles": ["registrant"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn",      {}, "text", "Test Owner"]
				]]
			}
		]
	}`)

	rec, err := parseDomain(data)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "example.com" {
		t.Errorf("Name = %q, want example.com", rec.Name)
	}
	if len(rec.Status) != 1 || rec.Status[0] != "active" {
		t.Errorf("Status = %v", rec.Status)
	}
	if rec.Registered != "1995-08-14" {
		t.Errorf("Registered = %q, want 1995-08-14", rec.Registered)
	}
	if rec.Updated != "2023-08-13" {
		t.Errorf("Updated = %q, want 2023-08-13", rec.Updated)
	}
	if rec.Expires != "2026-08-13" {
		t.Errorf("Expires = %q, want 2026-08-13", rec.Expires)
	}
	if len(rec.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", rec.Nameservers)
	}
	if rec.Registrar != "Test Registrar LLC" {
		t.Errorf("Registrar = %q", rec.Registrar)
	}
	if rec.Registrant != "Test Owner" {
		t.Errorf("Registrant = %q", rec.Registrant)
	}
}

func TestParseIP(t *testing.T) {
	data := []byte(`{
		"handle": "NET-8-8-8-0-2",
		"name": "GOGL",
		"startAddress": "8.8.8.0",
		"endAddress": "8.8.8.255",
		"ipVersion": "v4",
		"country": "US",
		"entities": [
			{
				"roles": ["registrant"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn",      {}, "text", "Google LLC"]
				]]
			}
		]
	}`)

	rec, err := parseIP(data)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q", rec.Handle)
	}
	if rec.Name != "GOGL" {
		t.Errorf("Name = %q", rec.Name)
	}
	if rec.StartAddr != "8.8.8.0" {
		t.Errorf("StartAddr = %q", rec.StartAddr)
	}
	if rec.EndAddr != "8.8.8.255" {
		t.Errorf("EndAddr = %q", rec.EndAddr)
	}
	if rec.Type != "IPv4 Network" {
		t.Errorf("Type = %q", rec.Type)
	}
	if rec.Country != "US" {
		t.Errorf("Country = %q", rec.Country)
	}
	if rec.Org != "Google LLC" {
		t.Errorf("Org = %q", rec.Org)
	}
}

func TestParseASN(t *testing.T) {
	data := []byte(`{
		"handle": "AS15169",
		"name": "GOOGLE",
		"startAutnum": 15169,
		"endAutnum": 15169,
		"country": "US",
		"entities": [
			{
				"roles": ["registrant"],
				"vcardArray": ["vcard", [
					["version", {}, "text", "4.0"],
					["fn",      {}, "text", "Google LLC"]
				]]
			}
		]
	}`)

	rec, err := parseASN(data)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Handle != "AS15169" {
		t.Errorf("Handle = %q", rec.Handle)
	}
	if rec.Name != "GOOGLE" {
		t.Errorf("Name = %q", rec.Name)
	}
	if rec.StartASN != 15169 {
		t.Errorf("StartASN = %d", rec.StartASN)
	}
	if rec.EndASN != 15169 {
		t.Errorf("EndASN = %d", rec.EndASN)
	}
	if rec.Country != "US" {
		t.Errorf("Country = %q", rec.Country)
	}
	if rec.Org != "Google LLC" {
		t.Errorf("Org = %q", rec.Org)
	}
}

func TestShortDate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1995-08-14T04:00:00Z", "1995-08-14"},
		{"2026-08-13", "2026-08-13"},
		{"20", "20"},
	}
	for _, tc := range cases {
		got := shortDate(tc.in)
		if got != tc.want {
			t.Errorf("shortDate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
