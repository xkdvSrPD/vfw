package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"vfw/internal/buildinfo"
	"vfw/internal/firewall"
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

	inputJumpPresent, inputJumpErr := a.fw.InputJumpPresent(ctx)
	runtimeStatus := "inactive"
	if inputJumpPresent {
		runtimeStatus = "active"
	}

	desiredCounts, desiredErr := a.ruleDesiredCounts(ctx, rules)
	ipsetCounts, existingSets, setCountErr := a.ruleLoadedCounts(ctx, rules)
	chains, chainsErr := a.fw.ListVFWChains(ctx)
	sets, setsErr := a.fw.ListVFWSets(ctx)

	fmt.Fprintf(a.out, "Status: %s\n", runtimeStatus)
	fmt.Fprintf(a.out, "Configured State: %s\n", boolLabel(state.Enabled))
	if inputJumpErr != nil {
		fmt.Fprintf(a.out, "Kernel State Check: %v\n", inputJumpErr)
	}
	if state.Enabled != inputJumpPresent {
		fmt.Fprintln(a.out, "State Drift: configured state does not match kernel jump state")
	}
	fmt.Fprintf(a.out, "Version: %s\n", buildinfo.Summary())
	fmt.Fprintf(a.out, "Rule Count: %d\n", len(rules))
	fmt.Fprintf(a.out, "Refresh Days: %d\n", a.cfg.RefreshDays)
	fmt.Fprintf(a.out, "Last Refresh: %s\n", formatTime(state.LastRefreshAt))
	fmt.Fprintf(a.out, "Last Update: %s\n", formatTime(state.UpdatedAt))
	fmt.Fprintf(a.out, "Config Dir: %s\n", a.cfg.ConfigDir)
	fmt.Fprintf(a.out, "Data Dir: %s\n", a.cfg.DataDir)
	fmt.Fprintf(a.out, "Log Dir: %s\n", a.cfg.LogDir)
	fmt.Fprintf(a.out, "ASN URL: %s\n", a.cfg.ASNURL)
	fmt.Fprintf(a.out, "Country URL: %s\n", a.cfg.CountryURL)
	fmt.Fprintf(a.out, "City URL: %s\n", a.cfg.CityURL)
	fmt.Fprintf(a.out, "iptables: %s\n", binarySummary(ctx, a.cfg.IPTablesBinary, "--version"))
	fmt.Fprintf(a.out, "ipset: %s\n", binarySummary(ctx, a.cfg.IPSetBinary, "version"))
	fmt.Fprintf(a.out, "ASN DB: %s\n", fileSummary(a.cfg.ASNDBPath()))
	fmt.Fprintf(a.out, "Country DB: %s\n", fileSummary(a.cfg.CountryDBPath()))
	fmt.Fprintf(a.out, "City DB: %s\n", fileSummary(a.cfg.CityDBPath()))

	if chainsErr != nil {
		fmt.Fprintf(a.out, "VFW Chains: error: %v\n", chainsErr)
	} else {
		fmt.Fprintf(a.out, "VFW Chains: %d", len(chains))
		if len(chains) > 0 {
			fmt.Fprintf(a.out, " (%s)", strings.Join(chains, ", "))
		}
		fmt.Fprintln(a.out)
	}
	if setsErr != nil {
		fmt.Fprintf(a.out, "VFW Sets: error: %v\n", setsErr)
	} else {
		fmt.Fprintf(a.out, "VFW Sets: %d", len(sets))
		if len(sets) > 0 {
			fmt.Fprintf(a.out, " (%s)", strings.Join(sets, ", "))
		}
		fmt.Fprintln(a.out)
	}
	if desiredErr != nil {
		fmt.Fprintf(a.out, "Desired Entry Resolution: %v\n", desiredErr)
	}
	if setCountErr != nil {
		fmt.Fprintf(a.out, "Loaded Entry Inspection: %v\n", setCountErr)
	}

	if len(rules) == 0 {
		return nil
	}

	rows := make([][]string, 0, len(rules))
	for index, rule := range rules {
		loaded := "-"
		if rule.Source.Type == model.SourceAll {
			if _, ok := existingSets[rule.SetName]; ok {
				loaded = "unused"
			}
		} else if count, ok := ipsetCounts[rule.SetName]; ok {
			loaded = strconv.Itoa(count)
		} else if state.Enabled {
			loaded = "missing"
		}

		rows = append(rows, []string{
			strconv.Itoa(index + 1),
			strconv.Itoa(rule.Port),
			rule.ProtocolLabel(),
			rule.SourceLabel(),
			desiredCounts[rule.SetName],
			loaded,
			rule.SetName,
			rule.CanonicalCommand(),
		})
	}

	fmt.Fprintln(a.out)
	fmt.Fprint(a.out, table.Render(
		[]string{"#", "PORT", "PROTO", "FROM", "DESIRED", "LOADED", "IPSET", "COMMAND"},
		rows,
	))
	return nil
}

func (a *App) ruleDesiredCounts(ctx context.Context, rules []model.Rule) (map[string]string, error) {
	counts := make(map[string]string, len(rules))
	needsMMDB := false
	for _, rule := range rules {
		switch rule.Source.Type {
		case model.SourceAll:
			counts[rule.SetName] = "all"
		case model.SourceIP:
			counts[rule.SetName] = strconv.Itoa(len(rule.Source.Values))
		default:
			counts[rule.SetName] = "?"
			needsMMDB = true
		}
	}
	if !needsMMDB {
		return counts, nil
	}
	if err := a.mmdb.EnsureDatabases(ctx, false); err != nil {
		return counts, err
	}
	resolved, err := a.mmdb.ResolveRules(ctx, rules)
	if err != nil {
		return counts, err
	}
	for _, rule := range rules {
		if rule.Source.Type == model.SourceASN || rule.Source.Type == model.SourceCountry || rule.Source.Type == model.SourceCity {
			counts[rule.SetName] = strconv.Itoa(len(resolved[rule.SetName]))
		}
	}
	return counts, nil
}

func (a *App) ruleLoadedCounts(ctx context.Context, rules []model.Rule) (map[string]int, map[string]struct{}, error) {
	setNames, err := a.fw.ListVFWSets(ctx)
	if err != nil {
		return nil, nil, err
	}
	existing := make(map[string]struct{}, len(setNames))
	for _, setName := range setNames {
		existing[setName] = struct{}{}
	}
	counts := make(map[string]int)
	for _, rule := range rules {
		if _, ok := existing[rule.SetName]; !ok {
			continue
		}
		if rule.Source.Type == model.SourceAll {
			continue
		}
		count, err := a.fw.SetEntryCount(ctx, rule.SetName)
		if err != nil {
			return counts, existing, err
		}
		counts[rule.SetName] = count
	}
	return counts, existing, nil
}

func binarySummary(ctx context.Context, binary string, versionArg string) string {
	path, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Sprintf("missing (%v)", err)
	}
	output, err := (firewall.OSExecutor{}).Run(ctx, path, versionArg)
	if err != nil {
		return fmt.Sprintf("%s (version error: %v)", path, err)
	}
	return fmt.Sprintf("%s [%s]", path, strings.ReplaceAll(strings.TrimSpace(output), "\n", " | "))
}

func fileSummary(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("missing (%s)", path)
	}
	return fmt.Sprintf("present size=%d modified=%s path=%s", info.Size(), info.ModTime().UTC().Format(time.RFC3339), path)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return value.UTC().Format(time.RFC3339)
}

func boolLabel(value bool) string {
	if value {
		return "active"
	}
	return "inactive"
}
