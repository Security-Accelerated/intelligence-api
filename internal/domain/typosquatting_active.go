package domain

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// CheckActive performs DNS and HTTP liveness checks on each permutation using
// bounded concurrency. It populates the Registered and Live fields in-place.
func CheckActive(ctx context.Context, perms []Permutation, concurrency int) {
	if concurrency <= 0 {
		concurrency = 20
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range perms {
		wg.Add(1)
		go func(p *Permutation) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			checkOne(ctx, p)
		}(&perms[i])
	}

	wg.Wait()
}

func checkOne(ctx context.Context, p *Permutation) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	registered := isDNSRegistered(ctx, p.Domain)
	p.Registered = &registered

	if !registered {
		return
	}

	live := isHTTPLive(ctx, p.Domain)
	p.Live = &live
}

// isDNSRegistered checks whether the domain has any A records.
func isDNSRegistered(ctx context.Context, domain string) bool {
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

// isHTTPLive does a quick HEAD request (HTTPS first, then HTTP) and returns
// true if the server responds with any status code.
func isHTTPLive(ctx context.Context, domain string) bool {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+domain, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "IntelligenceAPI/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return true
	}
	return false
}
