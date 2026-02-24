package domain

import (
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
	for _, p := range perms {
		if p.Domain == "example.com" {
			t.Error("bitsquat should not include the original")
		}
	}
}
