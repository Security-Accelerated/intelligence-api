package domain

import (
	"fmt"
	"strings"
	"time"
)

// Risk component weights. Only components with data present contribute; the
// final score is renormalized over the weights of present components so a
// base-lookup-only request still produces a meaningful 0–100 score.
var riskWeights = map[string]float64{
	"threat_intel":     0.35,
	"reputation":       0.25,
	"ssl":              0.10,
	"security_headers": 0.10,
	"email_security":   0.10,
	"domain_age":       0.10,
}

// whoisDateLayouts covers the date formats commonly emitted by WHOIS servers.
var whoisDateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"2006.01.02",
}

// ComputeRiskScore derives a normalized aggregate risk score from the lookup
// results already present on the response. It reads through the per-lookup
// response wrappers, so it scores whatever the caller happened to request. It performs no network calls and is
// intended to run as post-processing after all lookups complete. now is
// injectable for tests.
func ComputeRiskScore(resp *DomainResponse, now time.Time) *RiskSummary {
	var components []RiskComponent

	if resp.ThreatIntel != nil {
		components = append(components, RiskComponent{
			Component: "threat_intel",
			Score:     clampScore(resp.ThreatIntel.Score),
			Detail:    fmt.Sprintf("aggregate threat intelligence score across %d providers", len(resp.ThreatIntel.Providers)),
		})
	}

	if resp.Reputation != nil {
		components = append(components, RiskComponent{
			Component: "reputation",
			Score:     clampScore(resp.Reputation.Score),
			Detail:    "DNS blocklist reputation score",
		})
	}

	if resp.SSL != nil && resp.SSLInfo() != nil {
		components = append(components, scoreSSL(resp.SSLInfo()))
	}

	if resp.Headers != nil {
		components = append(components, scoreSecurityHeaders(resp.Headers.SecurityHeaders))
	}

	if resp.EmailSecurity != nil && resp.EmailSecurityInfo() != nil {
		components = append(components, scoreEmailSecurity(resp.EmailSecurityInfo()))
	}

	if resp.Whois != nil && resp.Whois.CreatedDate != "" {
		if c, ok := scoreDomainAge(resp.Whois.CreatedDate, now); ok {
			components = append(components, c)
		}
	}

	if len(components) == 0 {
		return nil
	}

	totalWeight := 0.0
	weightedScore := 0.0
	for i := range components {
		w := riskWeights[components[i].Component]
		components[i].Weight = w
		totalWeight += w
		weightedScore += float64(components[i].Score) * w
	}

	score := 0
	if totalWeight > 0 {
		score = clampScore(int(weightedScore/totalWeight + 0.5))
	}

	return &RiskSummary{
		Score:      score,
		Level:      riskLevelFor(score),
		Components: components,
	}
}

func scoreSSL(ssl *SSLInfo) RiskComponent {
	c := RiskComponent{Component: "ssl"}
	switch {
	case ssl.Expired:
		c.Score = 80
		c.Detail = "certificate is expired"
	case ssl.DaysUntilExpiry <= 14:
		c.Score = 40
		c.Detail = fmt.Sprintf("certificate expires in %d days", ssl.DaysUntilExpiry)
	case ssl.DaysUntilExpiry <= 30:
		c.Score = 20
		c.Detail = fmt.Sprintf("certificate expires in %d days", ssl.DaysUntilExpiry)
	default:
		c.Detail = "certificate valid"
	}
	return c
}

func scoreSecurityHeaders(sh *SecurityHeaders) RiskComponent {
	c := RiskComponent{Component: "security_headers"}
	var missing []string
	if sh == nil {
		missing = []string{"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"}
	} else {
		if sh.StrictTransportSecurity == "" {
			missing = append(missing, "strict-transport-security")
		}
		if sh.ContentSecurityPolicy == "" {
			missing = append(missing, "content-security-policy")
		}
		if sh.XFrameOptions == "" {
			missing = append(missing, "x-frame-options")
		}
		if sh.XContentTypeOptions == "" {
			missing = append(missing, "x-content-type-options")
		}
		if sh.ReferrerPolicy == "" {
			missing = append(missing, "referrer-policy")
		}
	}
	c.Score = len(missing) * 10 // hygiene signal, max 50
	if len(missing) > 0 {
		c.Detail = "missing: " + strings.Join(missing, ", ")
	} else {
		c.Detail = "all common security headers present"
	}
	return c
}

func scoreEmailSecurity(es *EmailSecurityInfo) RiskComponent {
	c := RiskComponent{Component: "email_security"}
	var issues []string
	switch {
	case es.SPF == nil:
		c.Score += 20
		issues = append(issues, "no SPF record")
	case es.SPF.All == "+all":
		c.Score += 30
		issues = append(issues, "SPF allows all senders (+all)")
	}
	switch {
	case es.DMARC == nil:
		c.Score += 20
		issues = append(issues, "no DMARC record")
	case es.DMARC.Policy == "none":
		c.Score += 10
		issues = append(issues, "DMARC policy is none")
	}
	if len(issues) > 0 {
		c.Detail = strings.Join(issues, "; ")
	} else {
		c.Detail = "SPF and DMARC configured"
	}
	return c
}

func scoreDomainAge(createdDate string, now time.Time) (RiskComponent, bool) {
	created, ok := parseWhoisDate(createdDate)
	if !ok {
		return RiskComponent{}, false
	}
	age := now.Sub(created)
	c := RiskComponent{Component: "domain_age"}
	days := int(age.Hours() / 24)
	switch {
	case days < 0:
		return RiskComponent{}, false
	case days <= 30:
		c.Score = 70
	case days <= 90:
		c.Score = 50
	case days <= 365:
		c.Score = 25
	}
	c.Detail = fmt.Sprintf("domain registered %d days ago", days)
	return c, true
}

func parseWhoisDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range whoisDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

// riskLevelFor maps a 0–100 score to a risk level, using the same thresholds
// as ScoreThreatIntel for consistency across the API.
func riskLevelFor(score int) string {
	switch {
	case score == 0:
		return "none"
	case score <= 20:
		return "low"
	case score <= 50:
		return "medium"
	case score <= 80:
		return "high"
	default:
		return "critical"
	}
}
