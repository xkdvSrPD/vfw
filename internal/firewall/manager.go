package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"

	"vfw/internal/envcfg"
	"vfw/internal/model"
)

const baseChain = "VFW_INPUT"

// Manager applies vfw rules through iptables and ipset.
type Manager struct {
	cfg  envcfg.Config
	exec Executor
}

// NewManager constructs a firewall manager with the provided executor.
func NewManager(cfg envcfg.Config, executor Executor) *Manager {
	if executor == nil {
		executor = OSExecutor{}
	}
	return &Manager{cfg: cfg, exec: executor}
}

// CheckPrerequisites validates the target system and required binaries.
func (m *Manager) CheckPrerequisites() error {
	if err := ensureSupportedOS(); err != nil {
		return err
	}
	if _, err := exec.LookPath(m.cfg.IPSetBinary); err != nil {
		return fmt.Errorf("required binary %q was not found in PATH", m.cfg.IPSetBinary)
	}
	if _, err := exec.LookPath(m.cfg.IPTablesBinary); err != nil {
		return fmt.Errorf("required binary %q was not found in PATH", m.cfg.IPTablesBinary)
	}
	return nil
}

// Apply reconciles ipsets and iptables chains with the desired rule set.
func (m *Manager) Apply(ctx context.Context, rules []model.Rule, setEntries map[string][]string) error {
	if err := m.syncDesiredSets(ctx, rules, setEntries); err != nil {
		return err
	}
	if err := m.syncChains(ctx, rules); err != nil {
		return err
	}
	return m.cleanupStaleSets(ctx, rules)
}

// SyncSets incrementally updates all desired ipsets and destroys stale vfw sets.
func (m *Manager) SyncSets(ctx context.Context, rules []model.Rule, setEntries map[string][]string) error {
	if err := m.syncDesiredSets(ctx, rules, setEntries); err != nil {
		return err
	}
	return m.cleanupStaleSets(ctx, rules)
}

func (m *Manager) syncDesiredSets(ctx context.Context, rules []model.Rule, setEntries map[string][]string) error {
	for _, rule := range rules {
		if err := m.ensureSet(ctx, rule.SetName); err != nil {
			return err
		}
		currentMembers, err := m.readSetMembers(ctx, rule.SetName)
		if err != nil {
			return err
		}
		wantMembers := make(map[string]struct{}, len(setEntries[rule.SetName]))
		for _, value := range setEntries[rule.SetName] {
			wantMembers[value] = struct{}{}
		}
		var toAdd []string
		for value := range wantMembers {
			if _, ok := currentMembers[value]; !ok {
				toAdd = append(toAdd, value)
			}
		}
		var toDelete []string
		for value := range currentMembers {
			if _, ok := wantMembers[value]; !ok {
				toDelete = append(toDelete, value)
			}
		}
		sort.Strings(toAdd)
		sort.Strings(toDelete)
		for _, value := range toAdd {
			if _, err := m.exec.Run(ctx, m.cfg.IPSetBinary, "add", rule.SetName, value); err != nil {
				return fmt.Errorf("add %s to ipset %s: %w", value, rule.SetName, err)
			}
		}
		for _, value := range toDelete {
			if _, err := m.exec.Run(ctx, m.cfg.IPSetBinary, "del", rule.SetName, value); err != nil {
				return fmt.Errorf("remove %s from ipset %s: %w", value, rule.SetName, err)
			}
		}
	}

	return nil
}

func (m *Manager) cleanupStaleSets(ctx context.Context, rules []model.Rule) error {
	desired := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		desired[rule.SetName] = struct{}{}
	}
	existingSets, err := m.listVFWSetNames(ctx)
	if err != nil {
		return err
	}
	for _, setName := range existingSets {
		if _, ok := desired[setName]; ok {
			continue
		}
		if err := m.destroySet(ctx, setName); err != nil {
			return err
		}
	}
	return nil
}

// Disable removes vfw-managed iptables chains and every vfw ipset.
func (m *Manager) Disable(ctx context.Context) error {
	if err := m.removeBaseJump(ctx); err != nil {
		return err
	}
	chains, err := m.listVFWChains(ctx)
	if err != nil {
		return err
	}
	for _, chain := range chains {
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-F", chain); err != nil {
			return fmt.Errorf("flush chain %s: %w", chain, err)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(chains)))
	for _, chain := range chains {
		if chain == baseChain {
			continue
		}
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-X", chain); err != nil {
			return fmt.Errorf("delete chain %s: %w", chain, err)
		}
	}
	for _, chain := range chains {
		if chain == baseChain {
			if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-X", chain); err != nil {
				return fmt.Errorf("delete chain %s: %w", chain, err)
			}
		}
	}
	sets, err := m.listVFWSetNames(ctx)
	if err != nil {
		return err
	}
	for _, setName := range sets {
		if err := m.destroySet(ctx, setName); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ensureSet(ctx context.Context, setName string) error {
	_, err := m.exec.Run(ctx, m.cfg.IPSetBinary, "create", setName, "hash:net", "family", "inet", "hashsize", "1024", "maxelem", "1048576", "-exist")
	if err != nil {
		return fmt.Errorf("create ipset %s: %w", setName, err)
	}
	return nil
}

func (m *Manager) destroySet(ctx context.Context, setName string) error {
	_, err := m.exec.Run(ctx, m.cfg.IPSetBinary, "destroy", setName)
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
		return nil
	}
	return fmt.Errorf("destroy ipset %s: %w", setName, err)
}

func (m *Manager) readSetMembers(ctx context.Context, setName string) (map[string]struct{}, error) {
	output, err := m.exec.Run(ctx, m.cfg.IPSetBinary, "save", setName)
	if err != nil {
		return nil, fmt.Errorf("read ipset %s: %w", setName, err)
	}
	members := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] == "add" && fields[1] == setName {
			members[fields[2]] = struct{}{}
		}
	}
	return members, nil
}

func (m *Manager) listVFWSetNames(ctx context.Context) ([]string, error) {
	output, err := m.exec.Run(ctx, m.cfg.IPSetBinary, "list", "-name")
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "kernel error received") || strings.Contains(lower, "no sets defined") {
			return nil, nil
		}
		return nil, fmt.Errorf("list ipsets: %w", err)
	}
	var setNames []string
	for _, line := range strings.Split(output, "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, "vfw_") {
			setNames = append(setNames, name)
		}
	}
	sort.Strings(setNames)
	return setNames, nil
}

func (m *Manager) syncChains(ctx context.Context, rules []model.Rule) error {
	if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-N", baseChain); err != nil && !strings.Contains(strings.ToLower(err.Error()), "chain already exists") {
		return fmt.Errorf("ensure chain %s: %w", baseChain, err)
	}
	plans := buildPortPlans(rules)
	desiredChains := map[string]struct{}{baseChain: {}}
	for _, plan := range plans {
		desiredChains[plan.ChainName] = struct{}{}
	}
	existingChains, err := m.listVFWChains(ctx)
	if err != nil {
		return err
	}

	if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-F", baseChain); err != nil {
		return fmt.Errorf("flush chain %s: %w", baseChain, err)
	}
	for _, chain := range existingChains {
		if chain == baseChain {
			continue
		}
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-F", chain); err != nil {
			return fmt.Errorf("flush chain %s: %w", chain, err)
		}
	}
	for _, plan := range plans {
		if stringSliceContains(existingChains, plan.ChainName) {
			continue
		}
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-N", plan.ChainName); err != nil && !strings.Contains(strings.ToLower(err.Error()), "chain already exists") {
			return fmt.Errorf("create chain %s: %w", plan.ChainName, err)
		}
	}
	for _, chain := range existingChains {
		if _, ok := desiredChains[chain]; ok || chain == baseChain {
			continue
		}
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-X", chain); err != nil {
			return fmt.Errorf("delete chain %s: %w", chain, err)
		}
	}

	sort.Slice(plans, func(i, j int) bool {
		if plans[i].Protocol == plans[j].Protocol {
			return plans[i].Port < plans[j].Port
		}
		return plans[i].Protocol < plans[j].Protocol
	})

	for _, plan := range plans {
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-A", baseChain, "-p", string(plan.Protocol), "--dport", strconv.Itoa(plan.Port), "-j", plan.ChainName); err != nil {
			return fmt.Errorf("append base rule for %s/%d: %w", plan.Protocol, plan.Port, err)
		}
		if plan.AllowAll {
			if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-A", plan.ChainName, "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("append allow-all rule for %s: %w", plan.ChainName, err)
			}
			continue
		}
		sort.Strings(plan.SetNames)
		for _, setName := range plan.SetNames {
			if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-A", plan.ChainName, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("append set rule for %s: %w", plan.ChainName, err)
			}
		}
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-A", plan.ChainName, "-j", "DROP"); err != nil {
			return fmt.Errorf("append drop rule for %s: %w", plan.ChainName, err)
		}
	}

	if err := m.ensureBaseJump(ctx); err != nil {
		return err
	}
	return nil
}

func (m *Manager) ensureBaseJump(ctx context.Context) error {
	if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-C", "INPUT", "-j", baseChain); err == nil {
		return nil
	}
	if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-I", "INPUT", "1", "-j", baseChain); err != nil {
		return fmt.Errorf("insert INPUT jump: %w", err)
	}
	return nil
}

func (m *Manager) removeBaseJump(ctx context.Context) error {
	for {
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-C", "INPUT", "-j", baseChain); err != nil {
			return nil
		}
		if _, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-D", "INPUT", "-j", baseChain); err != nil {
			return fmt.Errorf("delete INPUT jump: %w", err)
		}
	}
}

func (m *Manager) listVFWChains(ctx context.Context) ([]string, error) {
	output, err := m.exec.Run(ctx, m.cfg.IPTablesBinary, "-w", "-S")
	if err != nil {
		return nil, fmt.Errorf("list iptables rules: %w", err)
	}
	seen := map[string]struct{}{}
	var chains []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "-N" && strings.HasPrefix(fields[1], "VFW_") {
			name := fields[1]
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			chains = append(chains, name)
		}
	}
	sort.Strings(chains)
	return chains, nil
}

type portPlan struct {
	Port      int
	Protocol  model.Protocol
	ChainName string
	AllowAll  bool
	SetNames  []string
}

func buildPortPlans(rules []model.Rule) []portPlan {
	type key struct {
		port     int
		protocol model.Protocol
	}
	plans := make(map[key]*portPlan)
	for _, rule := range rules {
		for _, protocol := range rule.Protocols {
			planKey := key{port: rule.Port, protocol: protocol}
			plan, ok := plans[planKey]
			if !ok {
				plan = &portPlan{
					Port:      rule.Port,
					Protocol:  protocol,
					ChainName: rule.PortChainName(protocol),
				}
				plans[planKey] = plan
			}
			if rule.Source.Type == model.SourceAll {
				plan.AllowAll = true
				plan.SetNames = nil
				continue
			}
			if plan.AllowAll || stringSliceContains(plan.SetNames, rule.SetName) {
				continue
			}
			plan.SetNames = append(plan.SetNames, rule.SetName)
		}
	}
	var result []portPlan
	for _, plan := range plans {
		result = append(result, *plan)
	}
	return result
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func ensureSupportedOS() error {
	if goruntime.GOOS != "linux" {
		return fmt.Errorf("vfw only supports ubuntu/debian servers with iptables/ipset")
	}
	buffer, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("read /etc/os-release: %w", err)
	}
	content := strings.ToLower(string(buffer))
	if strings.Contains(content, "id=ubuntu") || strings.Contains(content, "id=debian") || strings.Contains(content, "id_like=debian") {
		return nil
	}
	return fmt.Errorf("vfw only supports ubuntu/debian servers with iptables/ipset")
}
