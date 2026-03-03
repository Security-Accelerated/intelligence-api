package domain

import (
	"context"
	"testing"
)

func TestGeneratePermutations_ShallowProducesResults(t *testing.T) {
	perms, capped := GeneratePermutations("example.com", "shallow", 500)
	if len(perms) == 0 {
		t.Fatal("expected permutations, got none")
	}
	if capped {
		t.Error("expected capped=false for shallow on example.com")
	}
	// Shallow runs 4 algorithms: omission, swap, homoglyph, wrong TLD
	// Should produce a reasonable number of results.
	if len(perms) < 20 {
		t.Errorf("expected at least 20 permutations for shallow, got %d", len(perms))
	}
}

func TestGeneratePermutations_DeepProducesMore(t *testing.T) {
	shallow, _ := GeneratePermutations("example.com", "shallow", 500)
	deep, _ := GeneratePermutations("example.com", "deep", 500)
	if len(deep) <= len(shallow) {
		t.Errorf("deep (%d) should produce more than shallow (%d)", len(deep), len(shallow))
	}
}

func TestGeneratePermutations_MaxPermsCap(t *testing.T) {
	perms, capped := GeneratePermutations("example.com", "deep", 10)
	if len(perms) != 10 {
		t.Errorf("expected 10 permutations with cap, got %d", len(perms))
	}
	if !capped {
		t.Error("expected capped=true when cap is hit")
	}
}

func TestGeneratePermutations_PreservesTLD(t *testing.T) {
	perms, _ := GeneratePermutations("example.org", "shallow", 500)
	for _, p := range perms {
		if p.Technique == "wrong_tld" {
			continue // wrong_tld intentionally changes the TLD
		}
		if p.Technique == "missing_dot" {
			continue // missing_dot produces concatenated domains
		}
		if !hasSuffix(p.Domain, ".org") {
			t.Errorf("permutation %q (technique=%s) does not preserve .org TLD", p.Domain, p.Technique)
		}
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestGeneratePermutations_ExcludesOriginal(t *testing.T) {
	perms, _ := GeneratePermutations("example.com", "deep", 500)
	for _, p := range perms {
		if p.Domain == "example.com" {
			t.Error("original domain should not appear in permutations")
		}
	}
}

func TestGeneratePermutations_NoDuplicates(t *testing.T) {
	perms, _ := GeneratePermutations("example.com", "deep", 500)
	seen := make(map[string]struct{})
	for _, p := range perms {
		if _, ok := seen[p.Domain]; ok {
			t.Errorf("duplicate permutation: %q", p.Domain)
		}
		seen[p.Domain] = struct{}{}
	}
}

func TestGeneratePermutations_EmptyDomain(t *testing.T) {
	perms, _ := GeneratePermutations("", "shallow", 500)
	if len(perms) != 0 {
		t.Errorf("expected no permutations for empty domain, got %d", len(perms))
	}
}

func TestGeneratePermutations_NoTLD(t *testing.T) {
	perms, _ := GeneratePermutations("localhost", "shallow", 500)
	if len(perms) != 0 {
		t.Errorf("expected no permutations for domain without TLD, got %d", len(perms))
	}
}

func TestGeneratePermutations_ShortDomain(t *testing.T) {
	perms, _ := GeneratePermutations("ab.com", "shallow", 500)
	if len(perms) == 0 {
		t.Error("expected permutations for short domain")
	}
}

func TestGeneratePermutations_TechniqueLabels(t *testing.T) {
	perms, _ := GeneratePermutations("example.com", "deep", 500)
	techniques := make(map[string]bool)
	for _, p := range perms {
		techniques[p.Technique] = true
	}
	// Deep should produce results from all algorithm categories
	expected := []string{
		"character_omission", "character_swap", "homoglyph", "wrong_tld",
		"adjacent_char", "character_repeat", "vowel_swap", "addition", "bitsquatting",
	}
	for _, e := range expected {
		if !techniques[e] {
			t.Errorf("expected technique %q in deep results", e)
		}
	}
}

func TestGenOmission(t *testing.T) {
	perms := genOmission("test", "com")
	// "test" has 4 chars → 4 omissions: "est", "tst", "tet", "tes"
	if len(perms) != 4 {
		t.Errorf("expected 4 omissions, got %d", len(perms))
	}
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	for _, want := range []string{"est.com", "tst.com", "tet.com", "tes.com"} {
		if !domains[want] {
			t.Errorf("missing expected omission %q", want)
		}
	}
}

func TestGenSwap(t *testing.T) {
	perms := genSwap("test", "com")
	// "test" has 3 adjacent pairs → 3 swaps: "etst", "tset", "tets"
	if len(perms) != 3 {
		t.Errorf("expected 3 swaps, got %d", len(perms))
	}
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	if !domains["etst.com"] {
		t.Error("missing swap etst.com")
	}
	if !domains["tset.com"] {
		t.Error("missing swap tset.com")
	}
	if !domains["tets.com"] {
		t.Error("missing swap tets.com")
	}
}

func TestGenWrongTLD(t *testing.T) {
	perms := genWrongTLD("example", "com")
	found := false
	for _, p := range perms {
		if p.Domain == "example.net" {
			found = true
		}
		if p.Domain == "example.com" {
			t.Error("wrong TLD should not include the original TLD")
		}
	}
	if !found {
		t.Error("expected example.net in wrong TLD results")
	}
}

func TestGenHomoglyph_MultiChar(t *testing.T) {
	// "m" maps to "rn" among others
	perms := genHomoglyph("mom", "com")
	found := false
	for _, p := range perms {
		if p.Domain == "rnom.com" || p.Domain == "morn.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected multi-char homoglyph substitution (m→rn)")
	}
}

func TestGenRepeat(t *testing.T) {
	perms := genRepeat("ab", "com")
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	if !domains["aab.com"] {
		t.Error("missing repeat aab.com")
	}
	if !domains["abb.com"] {
		t.Error("missing repeat abb.com")
	}
}

func TestGenBitsquat(t *testing.T) {
	perms := genBitsquat("example", "com")
	if len(perms) == 0 {
		t.Fatal("expected bitsquat permutations")
	}
	domains := make(map[string]bool)
	for _, p := range perms {
		if p.Domain == "example.com" {
			t.Error("bitsquat should not include the original")
		}
		domains[p.Domain] = true
	}
	// 'e' (0x65) XOR bit 2 → 'a' (0x61)
	if !domains["axample.com"] {
		t.Error("expected axample.com (e→a bit flip)")
	}
	// 'x' (0x78) XOR bit 0 → 'y' (0x79)
	if !domains["eyample.com"] {
		t.Error("expected eyample.com (x→y bit flip)")
	}
	// 'e' (0x65) XOR bit 0 → 'd' (0x64)
	if !domains["dxample.com"] {
		t.Error("expected dxample.com (e→d bit flip)")
	}
}

// --- Additional algorithm tests ---

func TestGenAdjacentSub(t *testing.T) {
	perms := genAdjacentSub("test", "com")
	if len(perms) == 0 {
		t.Fatal("expected adjacent substitution permutations")
	}
	// 't' is adjacent to 'r','y','f','g' on QWERTY
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	if !domains["rest.com"] {
		t.Error("expected rest.com (t→r)")
	}
	if !domains["yest.com"] {
		t.Error("expected yest.com (t→y)")
	}
}

func TestGenAdjacentSub_NonQWERTYChar(t *testing.T) {
	// Characters not in the QWERTY map (e.g. hyphen) should be skipped
	perms := genAdjacentSub("a-b", "com")
	for _, p := range perms {
		// The hyphen at index 1 should not produce adjacent substitutions
		// Only 'a' and 'b' should be substituted
		if p.Domain == "" {
			t.Error("unexpected empty domain")
		}
	}
}

func TestGenVowelSwap(t *testing.T) {
	perms := genVowelSwap("test", "com")
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	// 'e' in test should swap to a, i, o, u
	if !domains["tast.com"] {
		t.Error("expected tast.com (e→a)")
	}
	if !domains["tist.com"] {
		t.Error("expected tist.com (e→i)")
	}
	if !domains["tost.com"] {
		t.Error("expected tost.com (e→o)")
	}
	if !domains["tust.com"] {
		t.Error("expected tust.com (e→u)")
	}
}

func TestGenVowelSwap_NoVowels(t *testing.T) {
	perms := genVowelSwap("fly", "com")
	if len(perms) != 0 {
		t.Errorf("expected no vowel swaps for consonant-only SLD, got %d", len(perms))
	}
}

func TestGenMissingDot(t *testing.T) {
	perms := genMissingDot("example", "com")
	if len(perms) == 0 {
		t.Fatal("expected missing dot permutations")
	}
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	// "example" + "com" = "examplecom", registered under common TLDs
	if !domains["examplecom.com"] {
		t.Error("expected examplecom.com")
	}
	if !domains["examplecom.net"] {
		t.Error("expected examplecom.net")
	}
}

func TestGenMissingDot_MultiLevelTLD(t *testing.T) {
	// For "example.co.uk", SLD="example", TLD="co.uk"
	// concat = "example" + "couk" = "examplecouk"
	perms := genMissingDot("example", "co.uk")
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	if !domains["examplecouk.com"] {
		t.Error("expected examplecouk.com for multi-level TLD")
	}
}

func TestGenAddition(t *testing.T) {
	perms := genAddition("ab", "com")
	if len(perms) == 0 {
		t.Fatal("expected addition permutations")
	}
	domains := make(map[string]bool)
	for _, p := range perms {
		domains[p.Domain] = true
	}
	// Should include prepend, insert, and append positions
	if !domains["aab.com"] {
		t.Error("expected aab.com (prepend 'a')")
	}
	if !domains["abb.com"] {
		t.Error("expected abb.com (insert 'b' after 'a')")
	}
	if !domains["abc.com"] {
		t.Error("expected abc.com (append 'c')")
	}
}

// --- splitDomain tests ---

func TestSplitDomain_Standard(t *testing.T) {
	sld, tld := splitDomain("example.com")
	if sld != "example" || tld != "com" {
		t.Errorf("splitDomain(example.com) = (%q, %q), want (example, com)", sld, tld)
	}
}

func TestSplitDomain_MultiLevelTLD(t *testing.T) {
	sld, tld := splitDomain("example.co.uk")
	if sld != "example" || tld != "co.uk" {
		t.Errorf("splitDomain(example.co.uk) = (%q, %q), want (example, co.uk)", sld, tld)
	}
}

func TestSplitDomain_NoDot(t *testing.T) {
	sld, tld := splitDomain("localhost")
	if sld != "localhost" || tld != "" {
		t.Errorf("splitDomain(localhost) = (%q, %q), want (localhost, \"\")", sld, tld)
	}
}

func TestSplitDomain_SingleCharSLD(t *testing.T) {
	sld, tld := splitDomain("x.com")
	if sld != "x" || tld != "com" {
		t.Errorf("splitDomain(x.com) = (%q, %q), want (x, com)", sld, tld)
	}
}

// --- LookupTyposquatting orchestrator tests ---

func TestLookupTyposquatting_DefaultsToShallow(t *testing.T) {
	resp, err := LookupTyposquatting(context.Background(), "example.com", TyposquattingOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Depth != "shallow" {
		t.Errorf("Depth = %q, want %q", resp.Depth, "shallow")
	}
}

func TestLookupTyposquatting_InvalidDepth(t *testing.T) {
	_, err := LookupTyposquatting(context.Background(), "example.com", TyposquattingOptions{Depth: "medium"})
	if err == nil {
		t.Fatal("expected error for invalid depth")
	}
}

func TestLookupTyposquatting_DefaultMaxPermutations(t *testing.T) {
	resp, err := LookupTyposquatting(context.Background(), "example.com", TyposquattingOptions{
		Depth: "deep",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Default cap is 500; deep on "example.com" produces many permutations
	if resp.Count > 500 {
		t.Errorf("Count = %d, should be capped at 500", resp.Count)
	}
}

func TestLookupTyposquatting_CustomMaxPermutations(t *testing.T) {
	resp, err := LookupTyposquatting(context.Background(), "example.com", TyposquattingOptions{
		Depth:           "deep",
		MaxPermutations: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Count != 5 {
		t.Errorf("Count = %d, want 5", resp.Count)
	}
	if !resp.Capped {
		t.Error("expected Capped=true")
	}
}

func TestLookupTyposquatting_ResponsePopulation(t *testing.T) {
	resp, err := LookupTyposquatting(context.Background(), "test.com", TyposquattingOptions{Depth: "shallow"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Domain != "test.com" {
		t.Errorf("Domain = %q, want %q", resp.Domain, "test.com")
	}
	if resp.Count != len(resp.Permutations) {
		t.Errorf("Count = %d, len(Permutations) = %d, should match", resp.Count, len(resp.Permutations))
	}
}
