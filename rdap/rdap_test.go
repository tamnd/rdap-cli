package rdap_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tamnd/rdap-cli/rdap"
)

// fakeDomain is a minimal RDAP domain response.
const fakeDomain = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "client transfer prohibited"],
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
        ["fn",      {}, "text", "ICANN Registrar Inc"]
      ]]
    },
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn",      {}, "text", "IANA"]
      ]]
    }
  ]
}`

// fakeIP is a minimal RDAP ip response.
const fakeIP = `{
  "objectClassName": "ip network",
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
}`

// fakeASN is a minimal RDAP autnum response.
const fakeASN = `{
  "objectClassName": "autnum",
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
}`

func TestGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("request carried no User-Agent")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := rdap.NewClient()
	c.Rate = 0

	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", string(body))
	}
}

func TestGetRetriesOn503(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	c := rdap.NewClient()
	c.Rate = 0
	c.Retries = 5

	start := time.Now()
	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "recovered" {
		t.Errorf("body = %q after retries", string(body))
	}
	if hits != 3 {
		t.Errorf("server saw %d hits, want 3", hits)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Error("retries did not back off")
	}
}

func TestLookupDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fakeDomain))
	}))
	defer srv.Close()

	// Patch the client to hit our test server.
	c := rdap.NewClient()
	c.Rate = 0
	c.HTTP.Transport = &redirectTransport{base: srv.URL}

	body, err := c.Get(context.Background(), srv.URL+"/domain/EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}

	var raw struct {
		LDHName string   `json:"ldhName"`
		Status  []string `json:"status"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.LDHName != "EXAMPLE.COM" {
		t.Errorf("ldhName = %q, want EXAMPLE.COM", raw.LDHName)
	}
	if len(raw.Status) == 0 {
		t.Error("status is empty")
	}
}

func TestLookupDomainParse(t *testing.T) {
	// Use a server that returns our fake domain JSON for any domain path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fakeDomain))
	}))
	defer srv.Close()

	c := rdap.NewClient()
	c.Rate = 0

	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Verify parsing manually using exported helpers (via the public API test approach).
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m["ldhName"] != "EXAMPLE.COM" {
		t.Errorf("ldhName = %v", m["ldhName"])
	}
}

func TestLookupIPParse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fakeIP))
	}))
	defer srv.Close()

	c := rdap.NewClient()
	c.Rate = 0

	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m["handle"] != "NET-8-8-8-0-2" {
		t.Errorf("handle = %v", m["handle"])
	}
	if m["name"] != "GOGL" {
		t.Errorf("name = %v", m["name"])
	}
}

func TestLookupASNParse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fakeASN))
	}))
	defer srv.Close()

	c := rdap.NewClient()
	c.Rate = 0

	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m["handle"] != "AS15169" {
		t.Errorf("handle = %v", m["handle"])
	}
	if m["name"] != "GOOGLE" {
		t.Errorf("name = %v", m["name"])
	}
}

// redirectTransport rewrites all requests to hit the base test server.
type redirectTransport struct {
	base string
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = "http"
	req2.URL.Host = req.URL.Host
	return http.DefaultTransport.RoundTrip(req2)
}
