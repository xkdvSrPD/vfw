package parser

import (
	"testing"

	"vfw/internal/model"
)

func TestParseAddRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		wantPort    int
		wantType    model.SourceType
		wantValues  []string
		wantProto   []model.Protocol
		expectError bool
	}{
		{
			name:      "default all sources and both protocols",
			args:      []string{"allow", "22"},
			wantPort:  22,
			wantType:  model.SourceAll,
			wantProto: []model.Protocol{model.ProtocolTCP, model.ProtocolUDP},
		},
		{
			name:       "country selector",
			args:       []string{"allow", "443", "from", "country", "cn,us", "tcp"},
			wantPort:   443,
			wantType:   model.SourceCountry,
			wantValues: []string{"CN", "US"},
			wantProto:  []model.Protocol{model.ProtocolTCP},
		},
		{
			name:       "asn selector with add prefix",
			args:       []string{"add", "allow", "8443", "from", "asn", "4134,4837"},
			wantPort:   8443,
			wantType:   model.SourceASN,
			wantValues: []string{"4134", "4837"},
			wantProto:  []model.Protocol{model.ProtocolTCP, model.ProtocolUDP},
		},
		{
			name:       "direct ip selector",
			args:       []string{"allow", "53", "from", "1.1.1.1,10.0.0.0/8", "udp"},
			wantPort:   53,
			wantType:   model.SourceIP,
			wantValues: []string{"1.1.1.1/32", "10.0.0.0/8"},
			wantProto:  []model.Protocol{model.ProtocolUDP},
		},
		{
			name:        "invalid country code",
			args:        []string{"allow", "80", "from", "country", "CHN"},
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rule, err := ParseAddRule(test.args)
			if test.expectError {
				if err == nil {
					t.Fatal("expected an error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAddRule returned error: %v", err)
			}
			if rule.Port != test.wantPort {
				t.Fatalf("port mismatch: got %d want %d", rule.Port, test.wantPort)
			}
			if rule.Source.Type != test.wantType {
				t.Fatalf("source type mismatch: got %s want %s", rule.Source.Type, test.wantType)
			}
			if len(rule.Source.Values) != len(test.wantValues) {
				t.Fatalf("source values length mismatch: got %v want %v", rule.Source.Values, test.wantValues)
			}
			for index, value := range test.wantValues {
				if rule.Source.Values[index] != value {
					t.Fatalf("source value %d mismatch: got %s want %s", index, rule.Source.Values[index], value)
				}
			}
			if len(rule.Protocols) != len(test.wantProto) {
				t.Fatalf("protocol length mismatch: got %v want %v", rule.Protocols, test.wantProto)
			}
			for index, protocol := range test.wantProto {
				if rule.Protocols[index] != protocol {
					t.Fatalf("protocol %d mismatch: got %s want %s", index, rule.Protocols[index], protocol)
				}
			}
		})
	}
}
