package firewall

import (
	"testing"

	"vfw/internal/model"
)

func TestBuildPortPlans(t *testing.T) {
	t.Parallel()

	rules := []model.Rule{
		{
			Port:      22,
			Source:    model.Source{Type: model.SourceCountry, Values: []string{"CN"}},
			Protocols: []model.Protocol{model.ProtocolTCP},
			SetName:   "vfw_rule_1",
		},
		{
			Port:      22,
			Source:    model.Source{Type: model.SourceCountry, Values: []string{"US"}},
			Protocols: []model.Protocol{model.ProtocolTCP},
			SetName:   "vfw_rule_2",
		},
		{
			Port:      53,
			Source:    model.Source{Type: model.SourceAll},
			Protocols: []model.Protocol{model.ProtocolUDP},
			SetName:   "vfw_rule_3",
		},
	}

	plans := buildPortPlans(rules)
	if len(plans) != 2 {
		t.Fatalf("unexpected plan count: got %d want 2", len(plans))
	}

	var sawTCP22 bool
	var sawUDP53 bool
	for _, plan := range plans {
		switch {
		case plan.Protocol == model.ProtocolTCP && plan.Port == 22:
			sawTCP22 = true
			if plan.AllowAll {
				t.Fatal("tcp/22 plan should not allow all")
			}
			if len(plan.SetNames) != 2 {
				t.Fatalf("tcp/22 plan should contain 2 sets, got %v", plan.SetNames)
			}
		case plan.Protocol == model.ProtocolUDP && plan.Port == 53:
			sawUDP53 = true
			if !plan.AllowAll {
				t.Fatal("udp/53 plan should allow all")
			}
		}
	}

	if !sawTCP22 || !sawUDP53 {
		t.Fatalf("missing expected plans: tcp22=%v udp53=%v", sawTCP22, sawUDP53)
	}
}

func TestCanonicalSetMember(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "1.1.1.1/32", want: "1.1.1.1"},
		{input: "10.0.0.0/8", want: "10.0.0.0/8"},
		{input: "  1.2.3.4  ", want: "1.2.3.4"},
	}

	for _, test := range tests {
		if got := canonicalSetMember(test.input); got != test.want {
			t.Fatalf("canonicalSetMember(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
