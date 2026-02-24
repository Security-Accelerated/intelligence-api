package domain

import "strings"

// QWERTY keyboard adjacency map for adjacent-key substitution.
var qwertyAdj = map[rune][]rune{
	'q': {'w', 'a'},
	'w': {'q', 'e', 'a', 's'},
	'e': {'w', 'r', 's', 'd'},
	'r': {'e', 't', 'd', 'f'},
	't': {'r', 'y', 'f', 'g'},
	'y': {'t', 'u', 'g', 'h'},
	'u': {'y', 'i', 'h', 'j'},
	'i': {'u', 'o', 'j', 'k'},
	'o': {'i', 'p', 'k', 'l'},
	'p': {'o', 'l'},
	'a': {'q', 'w', 's', 'z'},
	's': {'a', 'w', 'e', 'd', 'z', 'x'},
	'd': {'s', 'e', 'r', 'f', 'x', 'c'},
	'f': {'d', 'r', 't', 'g', 'c', 'v'},
	'g': {'f', 't', 'y', 'h', 'v', 'b'},
	'h': {'g', 'y', 'u', 'j', 'b', 'n'},
	'j': {'h', 'u', 'i', 'k', 'n', 'm'},
	'k': {'j', 'i', 'o', 'l', 'm'},
	'l': {'k', 'o', 'p'},
	'z': {'a', 's', 'x'},
	'x': {'z', 's', 'd', 'c'},
	'c': {'x', 'd', 'f', 'v'},
	'v': {'c', 'f', 'g', 'b'},
	'b': {'v', 'g', 'h', 'n'},
	'n': {'b', 'h', 'j', 'm'},
	'm': {'n', 'j', 'k'},
	'1': {'2', 'q'},
	'2': {'1', '3', 'q', 'w'},
	'3': {'2', '4', 'w', 'e'},
	'4': {'3', '5', 'e', 'r'},
	'5': {'4', '6', 'r', 't'},
	'6': {'5', '7', 't', 'y'},
	'7': {'6', '8', 'y', 'u'},
	'8': {'7', '9', 'u', 'i'},
	'9': {'8', '0', 'i', 'o'},
	'0': {'9', 'o', 'p'},
}

// Homoglyph substitution table. Values are strings to support multi-character
// substitutions like m→rn.
var homoglyphs = map[rune][]string{
	'a': {"à", "á", "â", "ã", "ä", "å", "ɑ", "а"},
	'b': {"d", "ƅ", "ʙ"},
	'c': {"ç", "ć", "ĉ", "ċ"},
	'd': {"b", "ɗ", "ď"},
	'e': {"è", "é", "ê", "ë", "ē", "ė"},
	'f': {"ƒ"},
	'g': {"ɡ", "ġ", "ğ"},
	'h': {"ĥ", "ħ"},
	'i': {"1", "l", "í", "ì", "î", "ï", "ı"},
	'j': {"ĵ"},
	'k': {"ĸ", "ķ"},
	'l': {"1", "i", "ĺ", "ľ", "ł"},
	'm': {"rn", "ɱ"},
	'n': {"ñ", "ń", "ň"},
	'o': {"0", "ò", "ó", "ô", "õ", "ö", "ø"},
	'p': {"ρ", "р"},
	'q': {"ɋ"},
	'r': {"ŗ", "ř"},
	's': {"ś", "š", "ş", "ș"},
	't': {"ţ", "ť", "ŧ"},
	'u': {"ù", "ú", "û", "ü", "ů"},
	'v': {"ν", "ʋ"},
	'w': {"ω", "ŵ", "ẁ", "ẃ", "ẅ"},
	'x': {"×"},
	'y': {"ý", "ÿ", "ŷ"},
	'z': {"ź", "ż", "ž"},
}

var vowels = []rune{'a', 'e', 'i', 'o', 'u'}

var commonTLDs = []string{
	"com", "net", "org", "info", "biz", "co", "io", "me", "xyz",
	"online", "site", "tech", "store", "app", "dev", "us", "uk", "de",
}

// splitDomain splits "example.com" into ("example", "com").
// For multi-level TLDs like "example.co.uk", it treats the first label as the
// SLD and everything after the first dot as the TLD.
func splitDomain(d string) (sld, tld string) {
	idx := strings.IndexByte(d, '.')
	if idx < 0 {
		return d, ""
	}
	return d[:idx], d[idx+1:]
}

// GeneratePermutations produces typosquatting candidates for the given domain.
// depth is "shallow" (4 algorithms) or "deep" (all 10).
// maxPerms caps the result after deduplication.
// Returns the permutations and whether the cap was hit.
func GeneratePermutations(domain string, depth string, maxPerms int) ([]Permutation, bool) {
	sld, tld := splitDomain(domain)
	if sld == "" || tld == "" {
		return nil, false
	}

	type generator struct {
		name string
		fn   func(string, string) []Permutation
	}

	shallow := []generator{
		{"character_omission", genOmission},
		{"character_swap", genSwap},
		{"homoglyph", genHomoglyph},
		{"wrong_tld", genWrongTLD},
	}

	deep := []generator{
		{"adjacent_char", genAdjacentSub},
		{"character_repeat", genRepeat},
		{"vowel_swap", genVowelSwap},
		{"missing_dot", genMissingDot},
		{"addition", genAddition},
		{"bitsquatting", genBitsquat},
	}

	var gens []generator
	gens = append(gens, shallow...)
	if depth == "deep" {
		gens = append(gens, deep...)
	}

	seen := make(map[string]struct{})
	seen[domain] = struct{}{} // exclude the original
	var result []Permutation

	for _, g := range gens {
		for _, p := range g.fn(sld, tld) {
			if _, ok := seen[p.Domain]; ok {
				continue
			}
			seen[p.Domain] = struct{}{}
			p.Technique = g.name
			result = append(result, p)
		}
	}

	capped := false
	if maxPerms > 0 && len(result) > maxPerms {
		result = result[:maxPerms]
		capped = true
	}

	return result, capped
}

// --- Algorithm implementations ---

func genOmission(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i := range runes {
		candidate := string(runes[:i]) + string(runes[i+1:])
		if candidate == "" {
			continue
		}
		out = append(out, Permutation{Domain: candidate + "." + tld})
	}
	return out
}

func genSwap(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i := 0; i < len(runes)-1; i++ {
		swapped := make([]rune, len(runes))
		copy(swapped, runes)
		swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
		out = append(out, Permutation{Domain: string(swapped) + "." + tld})
	}
	return out
}

func genAdjacentSub(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i, r := range runes {
		adj, ok := qwertyAdj[r]
		if !ok {
			continue
		}
		for _, a := range adj {
			candidate := make([]rune, len(runes))
			copy(candidate, runes)
			candidate[i] = a
			out = append(out, Permutation{Domain: string(candidate) + "." + tld})
		}
	}
	return out
}

func genRepeat(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i, r := range runes {
		candidate := string(runes[:i+1]) + string(r) + string(runes[i+1:])
		out = append(out, Permutation{Domain: candidate + "." + tld})
	}
	return out
}

func genHomoglyph(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i, r := range runes {
		glyphs, ok := homoglyphs[r]
		if !ok {
			continue
		}
		for _, g := range glyphs {
			candidate := string(runes[:i]) + g + string(runes[i+1:])
			out = append(out, Permutation{Domain: candidate + "." + tld})
		}
	}
	return out
}

func genVowelSwap(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i, r := range runes {
		isVowel := false
		for _, v := range vowels {
			if r == v {
				isVowel = true
				break
			}
		}
		if !isVowel {
			continue
		}
		for _, v := range vowels {
			if v == r {
				continue
			}
			candidate := make([]rune, len(runes))
			copy(candidate, runes)
			candidate[i] = v
			out = append(out, Permutation{Domain: string(candidate) + "." + tld})
		}
	}
	return out
}

func genMissingDot(sld, tld string) []Permutation {
	var out []Permutation
	// Concatenation: someone types "examplecom" instead of "example.com"
	// Register that as a domain under common TLDs.
	concat := sld + strings.ReplaceAll(tld, ".", "")
	for _, t := range commonTLDs {
		out = append(out, Permutation{Domain: concat + "." + t})
	}
	return out
}

func genWrongTLD(sld, tld string) []Permutation {
	var out []Permutation
	for _, t := range commonTLDs {
		if t == tld {
			continue
		}
		out = append(out, Permutation{Domain: sld + "." + t})
	}
	return out
}

func genAddition(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	for _, ch := range chars {
		for i := 0; i <= len(runes); i++ {
			candidate := string(runes[:i]) + string(ch) + string(runes[i:])
			out = append(out, Permutation{Domain: candidate + "." + tld})
		}
	}
	return out
}

func genBitsquat(sld, tld string) []Permutation {
	runes := []rune(sld)
	var out []Permutation
	for i, r := range runes {
		// Only flip bits for ASCII alphanumeric characters
		if r > 127 {
			continue
		}
		for bit := 0; bit < 8; bit++ {
			flipped := r ^ (1 << bit)
			// Only keep valid domain label characters: lowercase letters and digits
			if (flipped >= 'a' && flipped <= 'z') || (flipped >= '0' && flipped <= '9') {
				if flipped == r {
					continue
				}
				candidate := make([]rune, len(runes))
				copy(candidate, runes)
				candidate[i] = flipped
				out = append(out, Permutation{Domain: string(candidate) + "." + tld})
			}
		}
	}
	return out
}
