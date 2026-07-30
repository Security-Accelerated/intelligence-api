package domain

import (
	"testing"
	"time"
)

var riskNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func TestComputeRiskScore_NoData(t *testing.T) {
	if got := ComputeRiskScore(&DomainResponse{Domain: "example.com"}, riskNow); got != nil {
		t.Errorf("expected nil risk summary with no lookup data, got %+v", got)
	}
}

func TestComputeRiskScore_CleanBaseLookups(t *testing.T) {
	resp := &DomainResponse{
		Whois: &WhoisResult{WhoisInfo: &WhoisInfo{CreatedDate: "1997-09-15T04:00:00Z"}},
		SSL:   &SSLResult{SSLInfo: &SSLInfo{DaysUntilExpiry: 200}},
		Headers: &HeadersResult{HeadersInfo: &HeadersInfo{
			StatusCode: 200,
			SecurityHeaders: &SecurityHeaders{
				StrictTransportSecurity: "max-age=63072000",
				ContentSecurityPolicy:   "default-src 'none'",
				XFrameOptions:           "DENY",
				XContentTypeOptions:     "nosniff",
				ReferrerPolicy:          "no-referrer",
			},
		}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	if risk.Score != 0 || risk.Level != "none" {
		t.Errorf("score = %d level = %s, want 0/none", risk.Score, risk.Level)
	}
	if len(risk.Components) != 3 {
		t.Errorf("components = %d, want 3 (ssl, security_headers, domain_age)", len(risk.Components))
	}
}

func TestComputeRiskScore_ThreatIntelDominates(t *testing.T) {
	resp := &DomainResponse{
		ThreatIntel: &ThreatIntelResult{ThreatIntelInfo: &ThreatIntelInfo{Score: 100, RiskLevel: "critical"}},
		Reputation:  &ReputationResult{ReputationInfo: &ReputationInfo{Score: 100, Risk: "critical"}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	if risk.Score != 100 {
		t.Errorf("score = %d, want 100", risk.Score)
	}
	if risk.Level != "critical" {
		t.Errorf("level = %s, want critical", risk.Level)
	}
}

func TestComputeRiskScore_ExpiredSSL(t *testing.T) {
	resp := &DomainResponse{
		SSL: &SSLResult{SSLInfo: &SSLInfo{Expired: true, DaysUntilExpiry: -10}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	// Only one component present — renormalized weight makes its score the total.
	if risk.Score != 80 {
		t.Errorf("score = %d, want 80", risk.Score)
	}
	if risk.Level != "high" {
		t.Errorf("level = %s, want high", risk.Level)
	}
}

func TestComputeRiskScore_MissingSecurityHeaders(t *testing.T) {
	resp := &DomainResponse{
		Headers: &HeadersResult{HeadersInfo: &HeadersInfo{StatusCode: 200, SecurityHeaders: nil}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	if risk.Score != 50 {
		t.Errorf("score = %d, want 50 (5 missing headers x 10)", risk.Score)
	}
}

func TestComputeRiskScore_EmailSecurityIssues(t *testing.T) {
	resp := &DomainResponse{
		EmailSecurity: &EmailSecurityResult{EmailSecurityInfo: &EmailSecurityInfo{
			SPF:   &SPFRecord{Raw: "v=spf1 +all", All: "+all"},
			DMARC: nil,
		}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	if risk.Score != 50 {
		t.Errorf("score = %d, want 50 (+all 30 + no DMARC 20)", risk.Score)
	}
}

func TestComputeRiskScore_NewDomain(t *testing.T) {
	resp := &DomainResponse{
		Whois: &WhoisResult{WhoisInfo: &WhoisInfo{CreatedDate: riskNow.AddDate(0, 0, -10).Format(time.RFC3339)}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	if risk.Score != 70 {
		t.Errorf("score = %d, want 70 (registered 10 days ago)", risk.Score)
	}
}

func TestComputeRiskScore_UnparsableWhoisDateSkipsComponent(t *testing.T) {
	resp := &DomainResponse{
		Whois: &WhoisResult{WhoisInfo: &WhoisInfo{CreatedDate: "before unixtime"}},
		SSL:   &SSLResult{SSLInfo: &SSLInfo{DaysUntilExpiry: 200}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	for _, c := range risk.Components {
		if c.Component == "domain_age" {
			t.Error("domain_age component should be skipped for unparsable date")
		}
	}
}

func TestComputeRiskScore_WeightsRenormalized(t *testing.T) {
	// threat_intel (0.35) at 100 and reputation (0.25) at 0 → 100*0.35/0.6 ≈ 58
	resp := &DomainResponse{
		ThreatIntel: &ThreatIntelResult{ThreatIntelInfo: &ThreatIntelInfo{Score: 100}},
		Reputation:  &ReputationResult{ReputationInfo: &ReputationInfo{Score: 0}},
	}
	risk := ComputeRiskScore(resp, riskNow)
	if risk == nil {
		t.Fatal("expected risk summary")
	}
	if risk.Score < 57 || risk.Score > 59 {
		t.Errorf("score = %d, want ~58 (renormalized over present weights)", risk.Score)
	}
	if risk.Level != "high" {
		t.Errorf("level = %s, want high", risk.Level)
	}
}

func TestParseWhoisDate_Layouts(t *testing.T) {
	cases := []string{
		"2020-05-04T10:20:30Z",
		"2020-05-04 10:20:30",
		"2020-05-04",
		"04-May-2020",
		"2020.05.04",
	}
	for _, s := range cases {
		if _, ok := parseWhoisDate(s); !ok {
			t.Errorf("parseWhoisDate(%q) failed", s)
		}
	}
	if _, ok := parseWhoisDate("not a date"); ok {
		t.Error("expected parse failure for invalid date")
	}
}
