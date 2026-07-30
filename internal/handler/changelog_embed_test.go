package handler

import "testing"

// TestEmbeddedChangelogParses guards the embedded changelog.yaml itself.
//
// Every other changelog test injects its own fixture data, so a malformed
// changelog.yaml only surfaced in the integration suite — which is build-tagged
// and not part of `make test`. A duplicate mapping key introduced while
// resolving a merge conflict is enough to make yaml.Unmarshal reject the whole
// file, after which the admin endpoint serves null and the docs page renders no
// release notes. That is exactly what happened, and nothing in the default test
// run noticed.
func TestEmbeddedChangelogParses(t *testing.T) {
	entries, err := parseChangelog()
	if err != nil {
		t.Fatalf("embedded changelog.yaml does not parse: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("embedded changelog.yaml parsed to zero versions")
	}

	for _, v := range entries {
		if v.Version == "" {
			t.Errorf("changelog entry has no version: %+v", v)
		}
		if v.Date == "" {
			t.Errorf("%s has no date", v.Version)
		}
		if len(v.Changes) == 0 {
			t.Errorf("%s has no changes", v.Version)
		}
		for i, c := range v.Changes {
			if c.Text == "" {
				t.Errorf("%s change %d has no text", v.Version, i)
			}
			// The docs page filters on this exact value; a typo silently hides
			// an entry from customers instead of failing.
			if c.Audience != "public" && c.Audience != "internal" {
				t.Errorf("%s change %d has audience %q, want public or internal", v.Version, i, c.Audience)
			}
		}
	}
}
