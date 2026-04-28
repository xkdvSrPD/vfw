// Package parser parses user-facing vfw CLI arguments.
package parser

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"vfw/internal/model"
)

// ParseAddRule parses both `vfw allow ...` and `vfw add allow ...` forms.
func ParseAddRule(args []string) (model.Rule, error) {
	if len(args) == 0 {
		return model.Rule{}, fmt.Errorf("missing rule arguments")
	}
	offset := 0
	if strings.EqualFold(args[0], "add") {
		offset++
	}
	if len(args[offset:]) < 2 {
		return model.Rule{}, fmt.Errorf("expected allow <port>")
	}
	if !strings.EqualFold(args[offset], "allow") {
		return model.Rule{}, fmt.Errorf("unsupported action %q", args[offset])
	}
	port, err := strconv.Atoi(args[offset+1])
	if err != nil {
		return model.Rule{}, fmt.Errorf("parse port: %w", err)
	}

	rule := model.Rule{
		Action:    "allow",
		Port:      port,
		Source:    model.Source{Type: model.SourceAll},
		CreatedAt: time.Now().UTC(),
	}

	remaining := append([]string(nil), args[offset+2:]...)
	if len(remaining) > 0 && isProtocolToken(remaining[len(remaining)-1]) {
		rule.Protocols = []model.Protocol{model.Protocol(strings.ToLower(remaining[len(remaining)-1]))}
		remaining = remaining[:len(remaining)-1]
	}
	if len(remaining) == 0 {
		if err := rule.EnsureDefaults(); err != nil {
			return model.Rule{}, err
		}
		return rule, nil
	}

	if strings.EqualFold(remaining[0], "from") {
		remaining = remaining[1:]
	}
	if len(remaining) == 0 {
		return model.Rule{}, fmt.Errorf("missing source selector after from")
	}

	switch {
	case len(remaining) == 1:
		values, err := normalizeIPValues(remaining[0])
		if err != nil {
			return model.Rule{}, err
		}
		rule.Source = model.Source{Type: model.SourceIP, Values: values}
	case len(remaining) == 2 && isSourceKeyword(remaining[0]):
		sourceType := model.SourceType(strings.ToLower(remaining[0]))
		values, err := normalizeTypedValues(sourceType, remaining[1])
		if err != nil {
			return model.Rule{}, err
		}
		rule.Source = model.Source{Type: sourceType, Values: values}
	default:
		return model.Rule{}, fmt.Errorf("unsupported source format, expected `from <ip[,cidr]>` or `from <asn|country|city> <values>`")
	}

	if err := rule.EnsureDefaults(); err != nil {
		return model.Rule{}, err
	}
	return rule, nil
}

func isProtocolToken(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(model.ProtocolTCP), string(model.ProtocolUDP):
		return true
	default:
		return false
	}
}

func isSourceKeyword(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(model.SourceASN), string(model.SourceCountry), string(model.SourceCity):
		return true
	default:
		return false
	}
}

func normalizeTypedValues(sourceType model.SourceType, raw string) ([]string, error) {
	parts := splitCSV(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("missing values for %s selector", sourceType)
	}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		switch sourceType {
		case model.SourceASN:
			if _, err := strconv.Atoi(part); err != nil {
				return nil, fmt.Errorf("invalid ASN %q", part)
			}
			values = append(values, part)
		case model.SourceCountry:
			if len(part) != 2 {
				return nil, fmt.Errorf("country code %q must be a 2-letter ISO code", part)
			}
			values = append(values, strings.ToUpper(part))
		case model.SourceCity:
			values = append(values, part)
		default:
			return nil, fmt.Errorf("unsupported source type %q", sourceType)
		}
	}
	return values, nil
}

func normalizeIPValues(raw string) ([]string, error) {
	parts := splitCSV(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("missing IP or CIDR values")
	}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if prefix, err := netip.ParsePrefix(part); err == nil {
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("IPv6 is not supported in iptables mode: %s", part)
			}
			values = append(values, prefix.Masked().String())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", part)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("IPv6 is not supported in iptables mode: %s", part)
		}
		values = append(values, netip.PrefixFrom(addr, 32).String())
	}
	return values, nil
}

func splitCSV(value string) []string {
	rawParts := strings.Split(value, ",")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}
