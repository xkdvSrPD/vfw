package app

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"vfw/internal/firewall"
	"vfw/internal/mmdb"
	"vfw/internal/model"
	"vfw/internal/table"
)

func (a *App) status(ctx context.Context) error {
	rules, err := a.store.LoadRules(ctx)
	if err != nil {
		return err
	}
	state, err := a.store.LoadState(ctx)
	if err != nil {
		return err
	}

	inputJumpPresent, _ := a.fw.InputJumpPresent(ctx)
	fmt.Fprintf(a.out, "Firewall: %s\n", firewallStatusLabel(state.Enabled, inputJumpPresent))
	fmt.Fprintf(a.out, "Pending Reload: %s\n", yesNoLabel(hasPendingReload(state, rules)))

	mmdbStatus, err := a.mmdb.Inspect(a.cfg.RefreshDays)
	if err != nil {
		fmt.Fprintf(a.out, "MMDB: error: %v\n", err)
	} else {
		fmt.Fprintf(a.out, "MMDB: %s\n", mmdbStatusLabel(mmdbStatus))
	}

	chainStats := a.collectChainStats(ctx, rules)

	rows, loadedSetCount, err := a.ipsetStatusRows(ctx, rules, chainStats)
	if err != nil {
		fmt.Fprintf(a.out, "IPSets: error: %v\n", err)
		return nil
	}
	fmt.Fprintf(a.out, "IPSets: %d loaded\n", loadedSetCount)
	if len(rows) == 0 {
		return nil
	}

	fmt.Fprintln(a.out)
	fmt.Fprint(a.out, table.Render(
		[]string{"#", "PORT", "FROM", "ENTRIES", "STATE", "ACCEPT", "DROP", "IPSET"},
		rows,
	))
	return nil
}

func (a *App) collectChainStats(ctx context.Context, rules []model.Rule) map[string]firewall.ChainStats {
	seen := map[string]struct{}{}
	for _, rule := range rules {
		for _, protocol := range rule.Protocols {
			seen[rule.PortChainName(protocol)] = struct{}{}
		}
	}
	stats := make(map[string]firewall.ChainStats, len(seen))
	for chainName := range seen {
		cs, err := a.fw.ChainStats(ctx, chainName)
		if err != nil {
			continue
		}
		stats[chainName] = cs
	}
	return stats
}

func (a *App) ipsetStatusRows(ctx context.Context, rules []model.Rule, chainStats map[string]firewall.ChainStats) ([][]string, int, error) {
	setNames, err := a.fw.ListVFWSets(ctx)
	if err != nil {
		return nil, 0, err
	}
	counts := make(map[string]int, len(setNames))
	for _, setName := range setNames {
		count, err := a.fw.SetEntryCount(ctx, setName)
		if err != nil {
			return nil, 0, err
		}
		counts[setName] = count
	}

	rows := make([][]string, 0, len(rules)+len(setNames))
	configured := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		configured[rule.SetName] = struct{}{}
		entryCount := "-"
		status := "missing"
		if count, ok := counts[rule.SetName]; ok {
			entryCount = strconv.Itoa(count)
			status = "loaded"
		}
		if rule.Source.Type == model.SourceAll {
			status = "all"
		}

		accepted, dropped := aggregateChainStats(rule, chainStats)

		rows = append(rows, []string{
			strconv.Itoa(index + 1),
			strconv.Itoa(rule.Port),
			rule.SourceLabel(),
			entryCount,
			status,
			accepted,
			dropped,
			rule.SetName,
		})
	}

	var staleSetNames []string
	for _, setName := range setNames {
		if _, ok := configured[setName]; ok {
			continue
		}
		staleSetNames = append(staleSetNames, setName)
	}
	sort.Strings(staleSetNames)
	for _, setName := range staleSetNames {
		rows = append(rows, []string{
			"-",
			"-",
			"-",
			strconv.Itoa(counts[setName]),
			"stale",
			"-",
			"-",
			setName,
		})
	}

	return rows, len(setNames), nil
}

func aggregateChainStats(rule model.Rule, chainStats map[string]firewall.ChainStats) (string, string) {
	var totalAcceptedPkts, totalAcceptedBytes uint64
	var totalDroppedPkts, totalDroppedBytes uint64

	for _, protocol := range rule.Protocols {
		cs, ok := chainStats[rule.PortChainName(protocol)]
		if !ok {
			return "-", "-"
		}
		totalAcceptedPkts += cs.AcceptedPkts
		totalAcceptedBytes += cs.AcceptedBytes
		totalDroppedPkts += cs.DroppedPkts
		totalDroppedBytes += cs.DroppedBytes
	}

	accept := fmt.Sprintf("%s / %s",
		table.FormatCount(totalAcceptedPkts),
		table.FormatBytes(totalAcceptedBytes),
	)
	drop := fmt.Sprintf("%s / %s",
		table.FormatCount(totalDroppedPkts),
		table.FormatBytes(totalDroppedBytes),
	)
	return accept, drop
}

func firewallStatusLabel(configuredEnabled bool, inputJumpPresent bool) string {
	switch {
	case configuredEnabled && inputJumpPresent:
		return "enabled"
	case !configuredEnabled && !inputJumpPresent:
		return "disabled"
	case configuredEnabled:
		return "drift (configured enabled, kernel disabled)"
	default:
		return "drift (configured disabled, kernel enabled)"
	}
}

func hasPendingReload(state model.State, rules []model.Rule) bool {
	if !state.LastConfigChangeAt.IsZero() {
		if state.LastAppliedAt.IsZero() {
			return true
		}
		return state.LastConfigChangeAt.After(state.LastAppliedAt)
	}
	lastRuleCreatedAt := latestRuleCreatedAt(rules)
	if lastRuleCreatedAt.IsZero() {
		return false
	}
	if state.LastAppliedAt.IsZero() {
		return true
	}
	return lastRuleCreatedAt.After(state.LastAppliedAt)
}

func latestRuleCreatedAt(rules []model.Rule) time.Time {
	var latest time.Time
	for _, rule := range rules {
		if rule.CreatedAt.After(latest) {
			latest = rule.CreatedAt
		}
	}
	return latest
}

func mmdbStatusLabel(status mmdb.DatabaseStatus) string {
	if len(status.Missing) > 0 {
		return fmt.Sprintf("missing (%s)", strings.Join(status.Missing, ", "))
	}
	if status.NeedsRefresh {
		return "needs update"
	}
	return "current"
}

func yesNoLabel(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
