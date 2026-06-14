package rdap

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/tamnd/any-cli/kit"
	"github.com/tamnd/any-cli/kit/errs"
)

// RegistryHost is the primary RDAP registry host, used as the kit Domain's
// scheme host for URI routing.
const RegistryHost = "rdap.arin.net"

func init() { kit.Register(Domain{}) }

// Domain is the rdap kit driver. It carries no state; the per-run client is
// built by the factory Register hands kit.
type Domain struct{}

// Info describes the scheme, the hostnames a pasted link is matched against,
// and the identity reused for the binary's help and version.
func (Domain) Info() kit.DomainInfo {
	return kit.DomainInfo{
		Scheme: "rdap",
		Hosts:  []string{RegistryHost, "rdap.verisign.com", "rdap.publicinterestregistry.org"},
		Identity: kit.Identity{
			Binary: "rdap",
			Short:  "Look up domain, IP, and ASN registration data via RDAP.",
			Long: `rdap queries RDAP (Registration Data Access Protocol) registries
to retrieve domain, IP, and ASN registration information. No API key needed.

Examples:
  rdap domain example.com
  rdap ip 8.8.8.8
  rdap asn 15169
  rdap lookup google.com`,
			Site: "https://rdap.arin.net",
			Repo: "https://github.com/tamnd/rdap-cli",
		},
	}
}

// Register installs the client factory and every operation onto app.
func (Domain) Register(app *kit.App) {
	app.SetClient(newClientFactory)

	kit.Handle(app, kit.OpMeta{Name: "domain", Group: "lookup", Single: true,
		Summary: "Look up domain registration data",
		Args:    []kit.Arg{{Name: "name", Help: "domain name (e.g. example.com)"}}}, lookupDomain)

	kit.Handle(app, kit.OpMeta{Name: "ip", Group: "lookup", Single: true,
		Summary: "Look up IP network registration",
		Args:    []kit.Arg{{Name: "address", Help: "IP address (e.g. 8.8.8.8)"}}}, lookupIP)

	kit.Handle(app, kit.OpMeta{Name: "asn", Group: "lookup", Single: true,
		Summary: "Look up ASN registration",
		Args:    []kit.Arg{{Name: "number", Help: "ASN number (e.g. 15169 or AS15169)"}}}, lookupASN)

	kit.Handle(app, kit.OpMeta{Name: "lookup", Group: "lookup", Single: true,
		Summary: "Auto-detect and look up domain, IP, or ASN",
		Args:    []kit.Arg{{Name: "query", Help: "domain name, IP address, or ASN (e.g. 8.8.8.8, AS15169, example.com)"}}}, autoLookup)
}

// newClientFactory builds the Client from kit config fields.
func newClientFactory(ctx context.Context, cfg kit.Config) (any, error) {
	c := newClient(ctx, cfg.Rate, cfg.Retries, cfg.Timeout, cfg.UserAgent)
	return c, nil
}

// --- input structs ---

type domainIn struct {
	Name   string  `kit:"arg" help:"domain name (e.g. example.com)"`
	Client *Client `kit:"inject"`
}

type ipIn struct {
	Address string  `kit:"arg" help:"IP address (e.g. 8.8.8.8)"`
	Client  *Client `kit:"inject"`
}

type asnIn struct {
	Number string  `kit:"arg" help:"ASN number (e.g. 15169 or AS15169)"`
	Client *Client `kit:"inject"`
}

type lookupIn struct {
	Query  string  `kit:"arg" help:"domain name, IP address, or ASN"`
	Client *Client `kit:"inject"`
}

// --- handlers ---

func lookupDomain(ctx context.Context, in domainIn, emit func(*DomainRecord) error) error {
	rec, err := in.Client.LookupDomain(ctx, in.Name)
	if err != nil {
		return mapErr(err)
	}
	return emit(rec)
}

func lookupIP(ctx context.Context, in ipIn, emit func(*IPRecord) error) error {
	rec, err := in.Client.LookupIP(ctx, in.Address)
	if err != nil {
		return mapErr(err)
	}
	return emit(rec)
}

func lookupASN(ctx context.Context, in asnIn, emit func(*ASNRecord) error) error {
	rec, err := in.Client.LookupASN(ctx, in.Number)
	if err != nil {
		return mapErr(err)
	}
	return emit(rec)
}

// autoLookup auto-detects the input type and routes to the right lookup.
// Because each type returns a different record type, we print JSON directly
// and emit nothing via the typed emitter — the kit framework handles the
// single-result case when the emitter is not called, so we use a workaround:
// each branch calls its own sub-handler and emits its record via a shared
// interface{}. Instead we keep it simple: three separate emit paths with
// a single polymorphic record. kit requires a single record type per op,
// so lookup emits a LookupResult that wraps all three.
func autoLookup(ctx context.Context, in lookupIn, emit func(*LookupResult) error) error {
	typ, id := classify(in.Query)
	switch typ {
	case "ip":
		rec, err := in.Client.LookupIP(ctx, id)
		if err != nil {
			return mapErr(err)
		}
		return emit(&LookupResult{Type: "ip", IP: rec})
	case "asn":
		rec, err := in.Client.LookupASN(ctx, id)
		if err != nil {
			return mapErr(err)
		}
		return emit(&LookupResult{Type: "asn", ASN: rec})
	default:
		rec, err := in.Client.LookupDomain(ctx, id)
		if err != nil {
			return mapErr(err)
		}
		return emit(&LookupResult{Type: "domain", Domain: rec})
	}
}

// LookupResult is the polymorphic output of the "lookup" command.
// Exactly one of Domain, IP, or ASN is populated.
type LookupResult struct {
	Type   string        `json:"type" kit:"id"`
	Domain *DomainRecord `json:"domain,omitempty"`
	IP     *IPRecord     `json:"ip,omitempty"`
	ASN    *ASNRecord    `json:"asn,omitempty"`
}

// --- Classify / Locate ---

// asnRE matches bare ASN numbers or AS-prefixed ones.
var asnRE = regexp.MustCompile(`^(?i:AS)?\d+$`)

// classify turns a user-supplied query into (type, canonical-id).
// Classify("8.8.8.8") → ("ip", "8.8.8.8")
// Classify("AS15169") or Classify("15169") → ("asn", "15169")
// Classify("example.com") → ("domain", "example.com")
func classify(input string) (typ, id string) {
	input = strings.TrimSpace(input)
	// IP address or CIDR?
	if net.ParseIP(input) != nil {
		return "ip", input
	}
	if _, _, err := net.ParseCIDR(input); err == nil {
		return "ip", input
	}
	// ASN: bare number or AS-prefixed
	if asnRE.MatchString(input) {
		num := strings.TrimPrefix(strings.ToUpper(input), "AS")
		return "asn", num
	}
	return "domain", strings.ToLower(input)
}

// Classify implements kit.Domain for URI resolution.
func (Domain) Classify(input string) (uriType, id string, err error) {
	typ, id := classify(input)
	return typ, id, nil
}

// Locate returns the canonical web URL for a (type, id) pair.
func (Domain) Locate(uriType, id string) (string, error) {
	switch uriType {
	case "domain":
		return fmt.Sprintf("https://lookup.icann.org/en/lookup?name=%s", id), nil
	case "ip":
		return fmt.Sprintf("https://search.arin.net/rdap/#/results/%s", id), nil
	case "asn":
		return fmt.Sprintf("https://search.arin.net/rdap/#/results/AS%s", id), nil
	default:
		return "", errs.Usage("rdap has no resource type %q", uriType)
	}
}

// mapErr converts library errors to kit error kinds.
func mapErr(err error) error {
	return err
}
