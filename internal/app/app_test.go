package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"vfw/internal/config"
	"vfw/internal/envcfg"
	"vfw/internal/firewall"
	"vfw/internal/mmdb"
	"vfw/internal/model"
)

func TestAddRuleOnlyUpdatesConfig(t *testing.T) {
	t.Parallel()

	testApp, _, executor := newTestApp(t)
	if err := testApp.addRule(context.Background(), []string{"allow", "22", "from", "1.1.1.1", "tcp"}); err != nil {
		t.Fatalf("addRule returned error: %v", err)
	}
	if got := len(executor.Commands()); got != 0 {
		t.Fatalf("addRule should not touch the firewall, got %d commands", got)
	}

	rules, err := testApp.store.LoadRules(context.Background())
	if err != nil {
		t.Fatalf("LoadRules returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("unexpected rule count: got %d want 1", len(rules))
	}

	state, err := testApp.store.LoadState(context.Background())
	if err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}
	if state.LastConfigChangeAt.IsZero() {
		t.Fatal("LastConfigChangeAt was not recorded")
	}
	if !state.LastAppliedAt.IsZero() {
		t.Fatalf("LastAppliedAt should stay zero, got %s", state.LastAppliedAt)
	}
}

func TestDeleteRuleOnlyUpdatesConfig(t *testing.T) {
	t.Parallel()

	testApp, _, executor := newTestApp(t)
	rule := mustRule(t, 443, model.Source{Type: model.SourceIP, Values: []string{"10.0.0.0/8"}}, []model.Protocol{model.ProtocolTCP})
	if err := testApp.store.SaveRules(context.Background(), []model.Rule{rule}); err != nil {
		t.Fatalf("SaveRules returned error: %v", err)
	}

	if err := testApp.deleteRule(context.Background(), []string{"1"}); err != nil {
		t.Fatalf("deleteRule returned error: %v", err)
	}
	if got := len(executor.Commands()); got != 0 {
		t.Fatalf("deleteRule should not touch the firewall, got %d commands", got)
	}

	rules, err := testApp.store.LoadRules(context.Background())
	if err != nil {
		t.Fatalf("LoadRules returned error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("unexpected rule count after delete: got %d want 0", len(rules))
	}

	state, err := testApp.store.LoadState(context.Background())
	if err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}
	if state.LastConfigChangeAt.IsZero() {
		t.Fatal("LastConfigChangeAt was not recorded")
	}
}

func TestRefreshAppliesPendingConfigWithoutDownloadingWhenMMDBCurrent(t *testing.T) {
	t.Parallel()

	testApp, _, executor := newTestApp(t)
	writeCurrentMMDBFiles(t, testApp.cfg)

	rule := mustRule(t, 53, model.Source{Type: model.SourceIP, Values: []string{"1.1.1.1/32"}}, []model.Protocol{model.ProtocolUDP})
	if err := testApp.store.SaveRules(context.Background(), []model.Rule{rule}); err != nil {
		t.Fatalf("SaveRules returned error: %v", err)
	}
	initialChangeAt := time.Now().UTC()
	state := model.State{
		Enabled:            true,
		LastConfigChangeAt: initialChangeAt,
	}
	if err := testApp.store.SaveState(context.Background(), state); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}

	if err := testApp.refresh(context.Background(), nil); err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}

	reloadedState, err := testApp.store.LoadState(context.Background())
	if err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}
	if reloadedState.LastAppliedAt.IsZero() || reloadedState.LastAppliedAt.Before(initialChangeAt) {
		t.Fatalf("refresh should record a new apply time, got %s", reloadedState.LastAppliedAt)
	}
	if !reloadedState.LastRefreshAt.IsZero() {
		t.Fatalf("refresh should not download current mmdb files, got LastRefreshAt=%s", reloadedState.LastRefreshAt)
	}

	if !executor.InputJumpPresent() {
		t.Fatal("refresh should apply the firewall jump when vfw is enabled")
	}
	if count := executor.SetEntryCount(rule.SetName); count != 1 {
		t.Fatalf("unexpected ipset entry count: got %d want 1", count)
	}
}

func TestStatusShowsSummaryOnly(t *testing.T) {
	t.Parallel()

	testApp, stdout, executor := newTestApp(t)
	writeCurrentMMDBFiles(t, testApp.cfg)

	rule := mustRule(t, 22, model.Source{Type: model.SourceIP, Values: []string{"1.1.1.1/32"}}, []model.Protocol{model.ProtocolTCP})
	if err := testApp.store.SaveRules(context.Background(), []model.Rule{rule}); err != nil {
		t.Fatalf("SaveRules returned error: %v", err)
	}
	if err := testApp.store.SaveState(context.Background(), model.State{
		Enabled:            true,
		LastConfigChangeAt: time.Now().UTC(),
		LastAppliedAt:      time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}
	executor.SetInputJump(true)
	executor.EnsureSet(rule.SetName)
	executor.AddSetEntry(rule.SetName, "1.1.1.1")
	executor.EnsureChain(rule.PortChainName(model.ProtocolTCP))

	if err := testApp.status(context.Background()); err != nil {
		t.Fatalf("status returned error: %v", err)
	}

	output := stdout.String()
	for _, needle := range []string{
		"Firewall: enabled",
		"Pending Reload: yes",
		"MMDB: current",
		"IPSets: 1 loaded",
		"ACCEPT",
		"DROP",
		rule.SetName,
	} {
		if !strings.Contains(output, needle) {
			t.Fatalf("status output missing %q:\n%s", needle, output)
		}
	}
	for _, needle := range []string{"Version:", "Config Dir:", "iptables:", "ASN URL:"} {
		if strings.Contains(output, needle) {
			t.Fatalf("status output should not contain %q:\n%s", needle, output)
		}
	}
}

func newTestApp(t *testing.T) (*App, *bytes.Buffer, *fakeExecutor) {
	t.Helper()

	tempDir := t.TempDir()
	cfg := envcfg.Config{
		ConfigDir:      tempDir,
		LogDir:         tempDir,
		DataDir:        tempDir,
		RefreshDays:    1,
		IPTablesBinary: "iptables",
		IPSetBinary:    "ipset",
	}
	executor := newFakeExecutor()
	stdout := &bytes.Buffer{}
	return &App{
		cfg:   cfg,
		store: config.NewStore(cfg.ConfigDir),
		mmdb:  mmdb.NewService(cfg),
		fw:    firewall.NewManager(cfg, executor),
		out:   stdout,
		err:   &bytes.Buffer{},
		checkPrerequisites: func() error {
			return nil
		},
	}, stdout, executor
}

func mustRule(t *testing.T, port int, source model.Source, protocols []model.Protocol) model.Rule {
	t.Helper()

	rule := model.Rule{
		Port:      port,
		Source:    source,
		Protocols: protocols,
	}
	if err := rule.EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults returned error: %v", err)
	}
	return rule
}

func writeCurrentMMDBFiles(t *testing.T, cfg envcfg.Config) {
	t.Helper()

	now := time.Now().UTC()
	for _, path := range []string{cfg.ASNDBPath(), cfg.CountryDBPath(), cfg.CityDBPath()} {
		if err := os.WriteFile(path, []byte("dummy"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) returned error: %v", path, err)
		}
		if err := os.Chtimes(path, now, now); err != nil {
			t.Fatalf("Chtimes(%s) returned error: %v", path, err)
		}
	}
}

type fakeExecutor struct {
	mu        sync.Mutex
	commands  []string
	inputJump bool
	sets      map[string]map[string]struct{}
	chains    map[string]struct{}
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{
		sets:   make(map[string]map[string]struct{}),
		chains: make(map[string]struct{}),
	}
}

func (f *fakeExecutor) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.commands = append(f.commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	switch name {
	case "ipset":
		return f.runIPSet(args)
	case "iptables":
		return f.runIPTables(args)
	default:
		return "", fmt.Errorf("unexpected binary %q", name)
	}
}

func (f *fakeExecutor) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	clone := make([]string, len(f.commands))
	copy(clone, f.commands)
	return clone
}

func (f *fakeExecutor) InputJumpPresent() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.inputJump
}

func (f *fakeExecutor) SetInputJump(value bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.inputJump = value
}

func (f *fakeExecutor) EnsureSet(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ensureSet(name)
}

func (f *fakeExecutor) AddSetEntry(name string, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ensureSet(name)
	f.sets[name][value] = struct{}{}
}

func (f *fakeExecutor) SetEntryCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.sets[name])
}

func (f *fakeExecutor) EnsureChain(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.chains[name] = struct{}{}
}

func (f *fakeExecutor) runIPSet(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("missing ipset arguments")
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			return "", fmt.Errorf("missing set name")
		}
		f.ensureSet(args[1])
		return "", nil
	case "save":
		if len(args) < 2 {
			return "", fmt.Errorf("missing set name")
		}
		setName := args[1]
		f.ensureSet(setName)
		var members []string
		for member := range f.sets[setName] {
			members = append(members, member)
		}
		sort.Strings(members)
		lines := make([]string, 0, len(members))
		for _, member := range members {
			lines = append(lines, fmt.Sprintf("add %s %s", setName, member))
		}
		return strings.Join(lines, "\n"), nil
	case "add":
		if len(args) < 3 {
			return "", fmt.Errorf("missing add arguments")
		}
		f.ensureSet(args[1])
		f.sets[args[1]][args[2]] = struct{}{}
		return "", nil
	case "del":
		if len(args) < 3 {
			return "", fmt.Errorf("missing del arguments")
		}
		delete(f.sets[args[1]], args[2])
		return "", nil
	case "destroy":
		if len(args) < 2 {
			return "", fmt.Errorf("missing set name")
		}
		delete(f.sets, args[1])
		return "", nil
	case "list":
		if len(args) < 2 {
			return "", fmt.Errorf("missing list arguments")
		}
		if args[1] == "-name" {
			var names []string
			for name := range f.sets {
				names = append(names, name)
			}
			sort.Strings(names)
			return strings.Join(names, "\n"), nil
		}
		setName := args[1]
		return fmt.Sprintf("Name: %s\nNumber of entries: %d\n", setName, len(f.sets[setName])), nil
	default:
		return "", fmt.Errorf("unexpected ipset arguments %q", strings.Join(args, " "))
	}
}

func (f *fakeExecutor) runIPTables(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("missing iptables arguments")
	}
	if args[0] == "-w" {
		args = args[1:]
	}
	if len(args) == 0 {
		return "", fmt.Errorf("missing iptables arguments")
	}
	switch args[0] {
	case "-C":
		if f.inputJump {
			return "", nil
		}
		return "", fmt.Errorf("rule not found")
	case "-I":
		f.inputJump = true
		return "", nil
	case "-D":
		f.inputJump = false
		return "", nil
	case "-N":
		if len(args) < 2 {
			return "", fmt.Errorf("missing chain name")
		}
		f.chains[args[1]] = struct{}{}
		return "", nil
	case "-F":
		return "", nil
	case "-X":
		if len(args) < 2 {
			return "", fmt.Errorf("missing chain name")
		}
		delete(f.chains, args[1])
		return "", nil
	case "-A":
		return "", nil
	case "-v":
		if len(args) >= 4 && args[1] == "-x" && args[2] == "-L" {
			chainName := args[3]
			if _, ok := f.chains[chainName]; !ok {
				return "", fmt.Errorf("chain %s does not exist", chainName)
			}
			return fmt.Sprintf(
				"Chain %s (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n    3421   215040 ACCEPT     tcp  --  any    any     0.0.0.0/0            0.0.0.0/0             match-set vfw_xxx src\n      89    10680 DROP       tcp  --  any    any     0.0.0.0/0            0.0.0.0/0\n",
				chainName,
			), nil
		}
		return "", fmt.Errorf("unexpected iptables -v arguments %q", strings.Join(args, " "))
	case "-S":
		var chains []string
		for chain := range f.chains {
			chains = append(chains, chain)
		}
		sort.Strings(chains)
		lines := make([]string, 0, len(chains))
		for _, chain := range chains {
			lines = append(lines, fmt.Sprintf("-N %s", chain))
		}
		return strings.Join(lines, "\n"), nil
	default:
		return "", fmt.Errorf("unexpected iptables arguments %q", strings.Join(args, " "))
	}
}

func (f *fakeExecutor) ensureSet(name string) {
	if _, ok := f.sets[name]; ok {
		return
	}
	f.sets[name] = make(map[string]struct{})
}
