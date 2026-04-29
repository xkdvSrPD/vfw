// Package model defines persisted firewall rules and runtime state.
package model

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxIPSetNameLength matches the Linux ipset name length limit.
	MaxIPSetNameLength = 31
)

// Protocol identifies the L4 protocol handled by a rule.
type Protocol string

const (
	// ProtocolTCP applies a rule to TCP traffic.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP applies a rule to UDP traffic.
	ProtocolUDP Protocol = "udp"
)

// SourceType identifies how a rule's source selector is resolved.
type SourceType string

const (
	// SourceAll allows traffic from every IPv4 source.
	SourceAll SourceType = "all"
	// SourceASN resolves prefixes from the ASN mmdb.
	SourceASN SourceType = "asn"
	// SourceCountry resolves prefixes from the country mmdb.
	SourceCountry SourceType = "country"
	// SourceCity resolves prefixes from the city mmdb.
	SourceCity SourceType = "city"
	// SourceIP uses direct IPv4 addresses or CIDRs.
	SourceIP SourceType = "ip"
)

// Rule is the persisted unit of configuration for vfw.
type Rule struct {
	ID        string     `json:"id"`
	Action    string     `json:"action"`
	Port      int        `json:"port"`
	Source    Source     `json:"source"`
	Protocols []Protocol `json:"protocols"`
	SetName   string     `json:"set_name"`
	CreatedAt time.Time  `json:"created_at"`
}

// Source describes how allowed source IPs are selected for a rule.
type Source struct {
	Type   SourceType `json:"type"`
	Values []string   `json:"values"`
}

// State stores runtime flags that are independent from the rule list.
type State struct {
	Enabled            bool      `json:"enabled"`
	LastRefreshAt      time.Time `json:"last_refresh_at"`
	LastConfigChangeAt time.Time `json:"last_config_change_at"`
	LastAppliedAt      time.Time `json:"last_applied_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// EnsureDefaults normalizes and completes a rule before persistence.
func (r *Rule) EnsureDefaults() error {
	if r.Action == "" {
		r.Action = "allow"
	}
	r.Action = strings.ToLower(r.Action)
	if r.Action != "allow" {
		return fmt.Errorf("unsupported action %q", r.Action)
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("port %d is out of range", r.Port)
	}
	if r.Source.Type == "" {
		r.Source.Type = SourceAll
	}
	if r.Source.Type == SourceAll {
		r.Source.Values = nil
	}
	if len(r.Protocols) == 0 {
		r.Protocols = []Protocol{ProtocolTCP, ProtocolUDP}
	}
	protocols := make([]Protocol, 0, len(r.Protocols))
	seen := make(map[Protocol]struct{}, len(r.Protocols))
	for _, protocol := range r.Protocols {
		p := Protocol(strings.ToLower(string(protocol)))
		switch p {
		case ProtocolTCP, ProtocolUDP:
		default:
			return fmt.Errorf("unsupported protocol %q", protocol)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		protocols = append(protocols, p)
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i] < protocols[j]
	})
	r.Protocols = protocols
	values := make([]string, 0, len(r.Source.Values))
	for _, value := range r.Source.Values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	r.Source.Values = values
	if r.ID == "" {
		r.ID = NewRuleID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.SetName == "" {
		r.SetName = BuildSetName(r.CanonicalCommand(), r.ID)
	}
	if len(r.SetName) > MaxIPSetNameLength {
		return fmt.Errorf("generated set name %q exceeds %d characters", r.SetName, MaxIPSetNameLength)
	}
	return nil
}

// NeedsMMDB reports whether the rule depends on mmdb-backed resolution.
func (r Rule) NeedsMMDB() bool {
	return r.Source.Type == SourceASN || r.Source.Type == SourceCountry || r.Source.Type == SourceCity
}

// ProtocolLabel returns the display form of the protocol selection.
func (r Rule) ProtocolLabel() string {
	values := make([]string, 0, len(r.Protocols))
	for _, protocol := range r.Protocols {
		values = append(values, string(protocol))
	}
	return strings.Join(values, ",")
}

// SourceLabel returns the display form of the source selector.
func (r Rule) SourceLabel() string {
	if r.Source.Type == SourceAll {
		return "all"
	}
	return fmt.Sprintf("%s %s", r.Source.Type, strings.Join(r.Source.Values, ","))
}

// CanonicalCommand returns the normalized CLI form for the rule.
func (r Rule) CanonicalCommand() string {
	parts := []string{"vfw", "allow", strconv.Itoa(r.Port)}
	if r.Source.Type != SourceAll {
		parts = append(parts, "from")
		if r.Source.Type != SourceIP {
			parts = append(parts, string(r.Source.Type))
		}
		parts = append(parts, strings.Join(r.Source.Values, ","))
	}
	if len(r.Protocols) == 1 {
		parts = append(parts, string(r.Protocols[0]))
	}
	return strings.Join(parts, " ")
}

// PortChainName returns the iptables chain name used for a specific protocol/port pair.
func (r Rule) PortChainName(protocol Protocol) string {
	tag := "T"
	if protocol == ProtocolUDP {
		tag = "U"
	}
	return fmt.Sprintf("VFW_%s_%d", tag, r.Port)
}

// NewRuleID creates a stable unique identifier for a rule.
func NewRuleID() string {
	buffer := make([]byte, 6)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("rule-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

// BuildSetName derives a deterministic ipset name from a canonical command and rule ID.
func BuildSetName(command string, ruleID string) string {
	hash := shortHash(command + "|" + ruleID)
	sanitized := sanitize(command)
	trimBudget := MaxIPSetNameLength - len("vfw__") - len(hash)
	if trimBudget < 0 {
		trimBudget = 0
	}
	if len(sanitized) > trimBudget {
		sanitized = sanitized[:trimBudget]
	}
	return fmt.Sprintf("vfw_%s_%s", sanitized, hash)
}

func sanitize(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	builder.Grow(len(value))
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	cleaned := strings.Trim(builder.String(), "_")
	for strings.Contains(cleaned, "__") {
		cleaned = strings.ReplaceAll(cleaned, "__", "_")
	}
	if cleaned == "" {
		return "rule"
	}
	return cleaned
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:4])
}
