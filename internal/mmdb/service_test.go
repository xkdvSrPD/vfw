package mmdb

import (
	"context"
	"testing"

	"vfw/internal/envcfg"
	"vfw/internal/model"
)

func TestResolveRulesWithoutMMDB(t *testing.T) {
	t.Parallel()

	service := NewService(envcfg.Config{})
	rules := []model.Rule{
		{
			Port:      22,
			Source:    model.Source{Type: model.SourceAll},
			Protocols: []model.Protocol{model.ProtocolTCP},
		},
		{
			Port:      53,
			Source:    model.Source{Type: model.SourceIP, Values: []string{"1.1.1.1/32", "10.0.0.0/8"}},
			Protocols: []model.Protocol{model.ProtocolUDP},
		},
	}
	for index := range rules {
		if err := rules[index].EnsureDefaults(); err != nil {
			t.Fatalf("EnsureDefaults(%d) returned error: %v", index, err)
		}
	}

	resolved, err := service.ResolveRules(context.Background(), rules)
	if err != nil {
		t.Fatalf("ResolveRules returned error: %v", err)
	}
	if len(resolved[rules[0].SetName]) != 1 || resolved[rules[0].SetName][0] != "0.0.0.0/0" {
		t.Fatalf("unexpected all-source resolution: %#v", resolved[rules[0].SetName])
	}
	if len(resolved[rules[1].SetName]) != 2 {
		t.Fatalf("unexpected IP-source resolution: %#v", resolved[rules[1].SetName])
	}
}

func TestNormalizeCityValue(t *testing.T) {
	t.Parallel()

	if got, want := normalizeCityValue("  ShangHai "), "shanghai"; got != want {
		t.Fatalf("normalizeCityValue mismatch: got %q want %q", got, want)
	}
}
