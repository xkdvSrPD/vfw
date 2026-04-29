// Package app wires the CLI, persistence, mmdb resolution, and firewall manager together.
package app

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"vfw/internal/buildinfo"
	"vfw/internal/config"
	"vfw/internal/envcfg"
	"vfw/internal/firewall"
	"vfw/internal/mmdb"
	"vfw/internal/model"
	"vfw/internal/parser"
	"vfw/internal/table"
)

// App is the top-level vfw CLI application.
type App struct {
	cfg   envcfg.Config
	store *config.Store
	mmdb  *mmdb.Service
	fw    *firewall.Manager
	out   io.Writer
	err   io.Writer

	checkPrerequisites func() error
}

// New constructs the CLI application with default dependencies.
func New(stdout io.Writer, stderr io.Writer) (*App, error) {
	cfg, err := envcfg.Load()
	if err != nil {
		return nil, err
	}
	manager := firewall.NewManager(cfg, nil)
	return &App{
		cfg:                cfg,
		store:              config.NewStore(cfg.ConfigDir),
		mmdb:               mmdb.NewService(cfg),
		fw:                 manager,
		out:                stdout,
		err:                stderr,
		checkPrerequisites: manager.CheckPrerequisites,
	}, nil
}

// Run executes a single vfw CLI invocation.
func (a *App) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return a.printUsage()
	}
	switch strings.ToLower(args[0]) {
	case "ls":
		return a.listRules(ctx)
	case "status":
		return a.status(ctx)
	case "version":
		return a.version()
	case "enable":
		return a.enable(ctx)
	case "disable":
		return a.disable(ctx)
	case "reload":
		return a.reload(ctx)
	case "refresh":
		return a.refresh(ctx, args[1:])
	case "del", "delete":
		return a.deleteRule(ctx, args[1:])
	case "add", "allow":
		return a.addRule(ctx, args)
	default:
		_ = a.printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (a *App) addRule(ctx context.Context, args []string) error {
	rule, err := parser.ParseAddRule(args)
	if err != nil {
		return err
	}
	rules, err := a.store.LoadRules(ctx)
	if err != nil {
		return err
	}
	rules = append(rules, rule)
	if err := a.store.SaveRules(ctx, rules); err != nil {
		return err
	}
	if err := a.markConfigChanged(ctx); err != nil {
		return fmt.Errorf("rule was saved but state update failed: %w", err)
	}
	fmt.Fprintf(a.out, "Added rule: %s\n\n", rule.CanonicalCommand())
	fmt.Fprint(a.out, table.RenderRules(rules))
	return nil
}

func (a *App) listRules(ctx context.Context) error {
	rules, err := a.store.LoadRules(ctx)
	if err != nil {
		return err
	}
	fmt.Fprint(a.out, table.RenderRules(rules))
	return nil
}

func (a *App) deleteRule(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected delete <index>")
	}
	index, err := strconv.Atoi(args[0])
	if err != nil || index < 1 {
		return fmt.Errorf("invalid rule index %q", args[0])
	}
	rules, err := a.store.LoadRules(ctx)
	if err != nil {
		return err
	}
	if index > len(rules) {
		return fmt.Errorf("rule index %d does not exist", index)
	}
	rules = append(rules[:index-1], rules[index:]...)
	if err := a.store.SaveRules(ctx, rules); err != nil {
		return err
	}
	if err := a.markConfigChanged(ctx); err != nil {
		return fmt.Errorf("rule was deleted from config but state update failed: %w", err)
	}
	fmt.Fprint(a.out, table.RenderRules(rules))
	return nil
}

func (a *App) enable(ctx context.Context) error {
	if err := a.systemPrerequisites(); err != nil {
		return err
	}
	fmt.Fprintln(a.err, "Warning: make sure SSH port 22 is already allowed before enabling vfw, or you may lose remote access.")

	rules, err := a.store.LoadRules(ctx)
	if err != nil {
		return err
	}
	downloaded, err := a.applyRules(ctx, rules)
	if err != nil {
		return err
	}
	state, err := a.store.LoadState(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	state.Enabled = true
	state.LastAppliedAt = now
	if downloaded {
		state.LastRefreshAt = now
	}
	state.UpdatedAt = now
	if err := a.store.SaveState(ctx, state); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "vfw is enabled.")
	if len(rules) > 0 {
		fmt.Fprintln(a.out)
		fmt.Fprint(a.out, table.RenderRules(rules))
	}
	return nil
}

func (a *App) disable(ctx context.Context) error {
	if err := a.systemPrerequisites(); err != nil {
		return err
	}
	if err := a.fw.Disable(ctx); err != nil {
		return err
	}
	state, err := a.store.LoadState(ctx)
	if err != nil {
		return err
	}
	state.Enabled = false
	state.UpdatedAt = time.Now().UTC()
	if err := a.store.SaveState(ctx, state); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "vfw is disabled.")
	return nil
}

func (a *App) reload(ctx context.Context) error {
	if err := a.systemPrerequisites(); err != nil {
		return err
	}
	state, err := a.store.LoadState(ctx)
	if err != nil {
		return err
	}
	if !state.Enabled {
		return fmt.Errorf("vfw is not enabled")
	}
	rules, err := a.store.LoadRules(ctx)
	if err != nil {
		return err
	}
	downloaded, err := a.applyRules(ctx, rules)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	state.LastAppliedAt = now
	if downloaded {
		state.LastRefreshAt = now
	}
	state.UpdatedAt = now
	if err := a.store.SaveState(ctx, state); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "vfw rules reloaded.")
	return nil
}

func (a *App) refresh(ctx context.Context, args []string) error {
	if err := a.systemPrerequisites(); err != nil {
		return err
	}
	force := len(args) == 1 && args[0] == "--force"
	if len(args) > 1 || (len(args) == 1 && !force) {
		return fmt.Errorf("usage: vfw refresh [--force]")
	}

	state, err := a.store.LoadState(ctx)
	if err != nil {
		return err
	}

	downloaded, err := a.mmdb.EnsureCurrent(ctx, a.cfg.RefreshDays, force)
	if err != nil {
		_ = envcfg.AppendLog(ctx, a.cfg, "refresh failed during mmdb download: "+err.Error())
		return err
	}

	reloaded := false
	if state.Enabled {
		rules, err := a.store.LoadRules(ctx)
		if err != nil {
			_ = envcfg.AppendLog(ctx, a.cfg, "refresh failed while reading rules: "+err.Error())
			return err
		}
		appliedDownload, err := a.applyRules(ctx, rules)
		if err != nil {
			_ = envcfg.AppendLog(ctx, a.cfg, "refresh failed while reloading active rules: "+err.Error())
			return err
		}
		downloaded = downloaded || appliedDownload
		reloaded = true
	}

	now := time.Now().UTC()
	if downloaded {
		state.LastRefreshAt = now
	}
	if reloaded {
		state.LastAppliedAt = now
	}
	state.UpdatedAt = now
	if err := a.store.SaveState(ctx, state); err != nil {
		return err
	}
	if err := envcfg.AppendLog(ctx, a.cfg, "refresh completed successfully"); err != nil {
		return err
	}
	if !downloaded && !reloaded {
		fmt.Fprintln(a.out, "refresh skipped: mmdb is current")
		return nil
	}
	fmt.Fprintf(a.out, "refresh completed at %s\n", now.Format(time.RFC3339))
	return nil
}

func (a *App) version() error {
	_, err := fmt.Fprintf(a.out, "vfw %s\n", buildinfo.Summary())
	return err
}

func (a *App) applyRules(ctx context.Context, rules []model.Rule) (bool, error) {
	needsMMDB := false
	for _, rule := range rules {
		if rule.NeedsMMDB() {
			needsMMDB = true
			break
		}
	}
	downloaded := false
	if needsMMDB {
		var err error
		downloaded, err = a.mmdb.EnsureCurrent(ctx, a.cfg.RefreshDays, false)
		if err != nil {
			return false, err
		}
	}
	setEntries, err := a.mmdb.ResolveRules(ctx, rules)
	if err != nil {
		return false, err
	}
	if err := a.fw.Apply(ctx, rules, setEntries); err != nil {
		return false, err
	}
	return downloaded, nil
}

func (a *App) printUsage() error {
	_, err := fmt.Fprintln(a.err, strings.TrimSpace(`
Usage:
  vfw allow <port> [from <ip[,cidr]>] [tcp|udp]
  vfw allow <port> [from] <asn|country|city> <values> [tcp|udp]
  vfw add allow <port> [from <selector>] [tcp|udp]
  vfw ls
  vfw status
  vfw version
  vfw delete <index>
  vfw enable
  vfw disable
  vfw reload
  vfw refresh [--force]
`))
	return err
}

func (a *App) markConfigChanged(ctx context.Context) error {
	state, err := a.store.LoadState(ctx)
	if err != nil {
		return err
	}
	state.LastConfigChangeAt = time.Now().UTC()
	return a.store.SaveState(ctx, state)
}

func (a *App) systemPrerequisites() error {
	if a.checkPrerequisites != nil {
		return a.checkPrerequisites()
	}
	return a.fw.CheckPrerequisites()
}
