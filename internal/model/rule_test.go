package model

import (
	"strings"
	"testing"
)

func TestCanonicalCommandAndSetName(t *testing.T) {
	t.Parallel()

	rule := Rule{
		Port:      443,
		Source:    Source{Type: SourceCountry, Values: []string{"CN", "US"}},
		Protocols: []Protocol{ProtocolTCP},
	}
	if err := rule.EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults returned error: %v", err)
	}
	if got, want := rule.CanonicalCommand(), "vfw allow 443 from country CN,US tcp"; got != want {
		t.Fatalf("CanonicalCommand mismatch: got %q want %q", got, want)
	}
	if len(rule.SetName) > MaxIPSetNameLength {
		t.Fatalf("set name exceeds limit: %q", rule.SetName)
	}
	if !strings.HasPrefix(rule.SetName, "vfw_") {
		t.Fatalf("set name missing prefix: %q", rule.SetName)
	}
}

func TestBuildSetNameIsDeterministic(t *testing.T) {
	t.Parallel()

	command := "vfw allow 22 from country CN tcp"
	ruleID := "fixed-id"
	first := BuildSetName(command, ruleID)
	second := BuildSetName(command, ruleID)
	if first != second {
		t.Fatalf("set name should be deterministic: %q != %q", first, second)
	}
}
