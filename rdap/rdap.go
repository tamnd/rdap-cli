// Package rdap is the library behind the rdap command line:
// the HTTP client, request shaping, and the typed data models for RDAP
// (Registration Data Access Protocol).
//
// The Client here is the spine every command shares. It sets a real
// User-Agent, paces requests so a busy session stays polite, and retries the
// transient failures (429 and 5xx) that public registries occasionally return.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultUserAgent identifies the client to RDAP registries.
const DefaultUserAgent = "rdap-cli/dev (+https://github.com/tamnd/rdap-cli)"

// BaseURLVerisign is the Verisign RDAP endpoint for .com and .net domains.
const BaseURLVerisign = "https://rdap.verisign.com/com/v1"

// BaseURLPIR is the Public Interest Registry RDAP endpoint for .org domains.
const BaseURLPIR = "https://rdap.publicinterestregistry.org/rdap"

// BaseURLARIN is the ARIN RDAP endpoint for IPs, ASNs, and other TLDs.
const BaseURLARIN = "https://rdap.arin.net/registry"

// DomainRecord holds the registration data for a domain name.
type DomainRecord struct {
	Name        string   `json:"name" kit:"id"`
	Status      []string `json:"status"`
	Registered  string   `json:"registered"`
	Updated     string   `json:"updated"`
	Expires     string   `json:"expires"`
	Nameservers []string `json:"nameservers"`
	Registrar   string   `json:"registrar"`
	Registrant  string   `json:"registrant"`
}

// IPRecord holds the registration data for an IP network block.
type IPRecord struct {
	Handle    string `json:"handle" kit:"id"`
	Name      string `json:"name"`
	StartAddr string `json:"start_address"`
	EndAddr   string `json:"end_address"`
	Type      string `json:"type"`
	Country   string `json:"country"`
	Org       string `json:"org"`
}

// ASNRecord holds the registration data for an Autonomous System Number.
type ASNRecord struct {
	Handle   string `json:"handle" kit:"id"`
	Name     string `json:"name"`
	StartASN int    `json:"start_asn"`
	EndASN   int    `json:"end_asn"`
	Country  string `json:"country"`
	Org      string `json:"org"`
}

// Config holds optional overrides for the client.
type Config struct {
	UserAgent string
	Rate      time.Duration
	Retries   int
	Timeout   time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Rate:    200 * time.Millisecond,
		Retries: 3,
		Timeout: 15 * time.Second,
	}
}

// Client talks to RDAP registries over HTTP.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	Rate      time.Duration
	Retries   int

	last time.Time
}

// NewClient returns a Client with sensible defaults.
func NewClient() *Client {
	cfg := DefaultConfig()
	return &Client{
		HTTP:      &http.Client{Timeout: cfg.Timeout},
		UserAgent: DefaultUserAgent,
		Rate:      cfg.Rate,
		Retries:   cfg.Retries,
	}
}

// newClient builds a Client from a kit.Config-compatible struct.
// Exported so domain.go's SetClient factory can call it.
func newClient(_ context.Context, rate time.Duration, retries int, timeout time.Duration, ua string) *Client {
	c := NewClient()
	if ua != "" {
		c.UserAgent = ua
	}
	if rate > 0 {
		c.Rate = rate
	}
	if retries > 0 {
		c.Retries = retries
	}
	if timeout > 0 {
		c.HTTP.Timeout = timeout
	}
	return c
}

// Get fetches a URL and returns the response body. It paces and retries
// according to the client's settings.
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		body, retry, err := c.do(ctx, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}
	return nil, fmt.Errorf("get %s: %w", url, lastErr)
}

func (c *Client) do(ctx context.Context, url string) (body []byte, retry bool, err error) {
	c.pace()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow redirects: Go's http.Client follows them automatically, but
	// some RDAP servers return 301/302 to the authoritative registry.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, true, fmt.Errorf("http %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("http %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, err
	}
	return b, false, nil
}

func (c *Client) pace() {
	if c.Rate <= 0 {
		return
	}
	if wait := c.Rate - time.Since(c.last); wait > 0 {
		time.Sleep(wait)
	}
	c.last = time.Now()
}

func backoff(attempt int) time.Duration {
	d := time.Duration(attempt) * 500 * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// LookupDomain fetches RDAP registration data for a domain name.
func (c *Client) LookupDomain(ctx context.Context, name string) (*DomainRecord, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	url := domainURL(name)
	body, err := c.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	return parseDomain(body)
}

// LookupIP fetches RDAP registration data for an IP address or CIDR block.
func (c *Client) LookupIP(ctx context.Context, addr string) (*IPRecord, error) {
	addr = strings.TrimSpace(addr)
	url := BaseURLARIN + "/ip/" + addr
	body, err := c.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("lookup ip %s: %w", addr, err)
	}
	return parseIP(body)
}

// LookupASN fetches RDAP registration data for an Autonomous System Number.
func (c *Client) LookupASN(ctx context.Context, asn string) (*ASNRecord, error) {
	asn = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(asn), "AS"))
	url := BaseURLARIN + "/autnum/" + asn
	body, err := c.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("lookup asn %s: %w", asn, err)
	}
	return parseASN(body)
}

// domainURL returns the best RDAP endpoint for a given domain name.
func domainURL(name string) string {
	tld := tldOf(name)
	switch tld {
	case "com", "net":
		return BaseURLVerisign + "/domain/" + strings.ToUpper(name)
	case "org":
		return BaseURLPIR + "/domain/" + name
	default:
		return BaseURLARIN + "/domain/" + name
	}
}

// tldOf returns the last label of a domain name.
func tldOf(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

// --- raw RDAP JSON shapes ---

type rdapDomain struct {
	LDHName     string       `json:"ldhName"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Nameservers []rdapNS     `json:"nameservers"`
	Entities    []rdapEntity `json:"entities"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Roles     []string `json:"roles"`
	VCardArray []any   `json:"vcardArray"`
	Entities  []rdapEntity `json:"entities"`
}

type rdapIP struct {
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	IPVersion    string       `json:"ipVersion"`
	Country      string       `json:"country"`
	Entities     []rdapEntity `json:"entities"`
}

type rdapASN struct {
	Handle     string       `json:"handle"`
	Name       string       `json:"name"`
	StartAutnum int         `json:"startAutnum"`
	EndAutnum   int         `json:"endAutnum"`
	Country    string       `json:"country"`
	Entities   []rdapEntity `json:"entities"`
}

// parseDomain converts raw RDAP JSON into a DomainRecord.
func parseDomain(data []byte) (*DomainRecord, error) {
	var raw rdapDomain
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse domain: %w", err)
	}
	r := &DomainRecord{
		Name:   strings.ToLower(raw.LDHName),
		Status: raw.Status,
	}
	for _, e := range raw.Events {
		switch e.Action {
		case "registration":
			r.Registered = shortDate(e.Date)
		case "last changed":
			r.Updated = shortDate(e.Date)
		case "expiration":
			r.Expires = shortDate(e.Date)
		}
	}
	for _, ns := range raw.Nameservers {
		if ns.LDHName != "" {
			r.Nameservers = append(r.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	r.Registrar = entityFN(raw.Entities, "registrar")
	r.Registrant = entityFN(raw.Entities, "registrant")
	return r, nil
}

// parseIP converts raw RDAP JSON into an IPRecord.
func parseIP(data []byte) (*IPRecord, error) {
	var raw rdapIP
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse ip: %w", err)
	}
	ipType := "IPv4 Network"
	if strings.ToLower(raw.IPVersion) == "v6" {
		ipType = "IPv6 Network"
	}
	return &IPRecord{
		Handle:    raw.Handle,
		Name:      raw.Name,
		StartAddr: raw.StartAddress,
		EndAddr:   raw.EndAddress,
		Type:      ipType,
		Country:   raw.Country,
		Org:       entityFN(raw.Entities, "registrant"),
	}, nil
}

// parseASN converts raw RDAP JSON into an ASNRecord.
func parseASN(data []byte) (*ASNRecord, error) {
	var raw rdapASN
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse asn: %w", err)
	}
	return &ASNRecord{
		Handle:   raw.Handle,
		Name:     raw.Name,
		StartASN: raw.StartAutnum,
		EndASN:   raw.EndAutnum,
		Country:  raw.Country,
		Org:      entityFN(raw.Entities, "registrant"),
	}, nil
}

// entityFN finds the first entity with the given role and returns its FN vCard field.
func entityFN(entities []rdapEntity, role string) string {
	for _, e := range entities {
		if !hasRole(e.Roles, role) {
			continue
		}
		if fn := vcardFN(e.VCardArray); fn != "" {
			return fn
		}
		// Some registries nest the name inside sub-entities.
		for _, sub := range e.Entities {
			if fn := vcardFN(sub.VCardArray); fn != "" {
				return fn
			}
		}
	}
	return ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// vcardFN extracts the FN (full name) field from a vcardArray.
// The shape is: ["vcard", [[field, params, type, value], ...]]
func vcardFN(vcardArray []any) string {
	if len(vcardArray) < 2 {
		return ""
	}
	props, ok := vcardArray[1].([]any)
	if !ok {
		return ""
	}
	for _, prop := range props {
		row, ok := prop.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		if name, ok := row[0].(string); ok && name == "fn" {
			if val, ok := row[3].(string); ok {
				return val
			}
		}
	}
	return ""
}

// shortDate trims an RFC 3339 timestamp to a YYYY-MM-DD date string.
func shortDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
