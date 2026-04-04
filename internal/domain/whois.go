package domain

import (
	"context"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

func LookupWhois(ctx context.Context, domain string) (*WhoisInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		raw, err := whois.Whois(domain)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- raw
	}()

	var raw string
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case raw = <-resultCh:
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return nil, err
	}

	return whoisInfoFromParsed(parsed), nil
}

func whoisInfoFromParsed(parsed whoisparser.WhoisInfo) *WhoisInfo {
	info := &WhoisInfo{}

	if parsed.Domain != nil {
		info.DomainName = parsed.Domain.Domain
		info.CreatedDate = parsed.Domain.CreatedDate
		info.UpdatedDate = parsed.Domain.UpdatedDate
		info.ExpiryDate = parsed.Domain.ExpirationDate
		info.Status = parsed.Domain.Status
		info.NameServers = parsed.Domain.NameServers
	}
	if parsed.Registrar != nil {
		info.Registrar = parsed.Registrar.Name
	}

	if c := contactFromWhois(parsed.Registrant); c != nil {
		info.Registrant = c
	}
	if c := contactFromWhois(parsed.Administrative); c != nil {
		info.Admin = c
	}
	if c := contactFromWhois(parsed.Technical); c != nil {
		info.Tech = c
	}

	return info
}

func contactFromWhois(c *whoisparser.Contact) *Contact {
	if c == nil {
		return nil
	}
	contact := &Contact{
		Name:         c.Name,
		Organization: c.Organization,
		Country:      c.Country,
		Email:        c.Email,
	}
	if strings.TrimSpace(contact.Name+contact.Organization+contact.Country+contact.Email) == "" {
		return nil
	}
	return contact
}
