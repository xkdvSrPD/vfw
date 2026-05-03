# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See [AGENTS.md](AGENTS.md) for detailed development constraints, remote test host setup, commit conventions, release process, and pre-merge checklist.

## Build & Test

```bash
go test ./...                          # run all tests
CGO_ENABLED=1 go test -race ./...      # race detector (required for concurrency/external-cmd changes)
make build                             # write dist/vfw (Go compile, linker flags for version/commit)
make test                              # go test ./...
make race                              # CGO_ENABLED=1 go test -race ./...
make deb VERSION=0.1.0 ARCH=amd64      # build .deb (requires dpkg-deb, Linux-only)
```

## Architecture

A one-shot CLI (no daemon) that manages `iptables`/`ipset` for IPv4 firewalling on Ubuntu/Debian.

```
cmd/vfw/main.go          CLI entrypoint, signal handling, delegates to app.App
internal/app/            Command orchestration: enable/disable/reload/refresh/status/add/delete/ls/version
internal/firewall/       iptables chain management + ipset create/destroy/sync (Executor interface for testability)
internal/mmdb/           GeoLite mmdb download (parallel HTTP), freshness checks, and CIDR resolution from ASN/country/city selectors
internal/parser/         CLI argument parsing: "vfw allow <port> [from <selector>] [tcp|udp]"
internal/model/          Core types: Rule (persisted), State (runtime flags), ipset name builder (31-char limit)
internal/config/         JSON persistence layer for /etc/vfw/rules.json and /etc/vfw/state.json (atomic writes via temp+rename)
internal/envcfg/         Environment variable loading (paths, mmdb URLs, refresh interval) and log writer
internal/buildinfo/      Build-time version/commit injection via linker flags
internal/table/          Terminal table rendering for "vfw ls" and "vfw status"
```

### Key data flow

1. `vfw allow` / `vfw delete` → parser → model.Rule → config.Store (writes rules.json only)
2. `vfw enable` / `vfw reload` → loads rules.json → mmdb.Service.ResolveRules (scans mmdb files) → firewall.Manager.Apply (syncs ipsets + iptables chains)
3. `vfw refresh` → mmdb.Service.EnsureCurrent (download if stale/forced) → optionally reloads active rules

### iptables chain layout

- A jump rule `INPUT → VFW_INPUT` is inserted at position 1 of the INPUT chain
- `VFW_INPUT` dispatches to per-port/protocol chains like `VFW_T_22`, `VFW_U_53`
- Each port chain has `ACCEPT` rules matching ipsets, then a final `DROP`
- `vfw disable` removes the INPUT jump, flushes all VFW chains, and destroys all `vfw_*` ipsets

### ipset naming

- Names are prefixed `vfw_`, derived from a sanitized canonical command + SHA1 hash to stay within the 31-char Linux kernel limit
- The persisted `rules.json` is the source of truth; never reconstruct rules from ipset names alone

### Idempotency guarantee

- `firewall.Manager.Apply` computes the diff between desired and actual state: adds/removes ipset members, creates/destroys chains
- `vfw disable` loops over the INPUT jump deletion to handle multiple jump rule copies

## Key constraints

- Linux IPv4 only; Go 1.24.0; module path `vfw`
- Runtime depends on `iptables` and `ipset` binaries (paths configurable via `VFW_IPTABLES_BIN`, `VFW_IPSET_BIN`)
- Firewall changes must never lock out the current SSH session
- `.gitea/workflows/*.yml` is the primary CI; keep `.github/workflows/release.yml` in sync
- Tests that touch concurrency or external command execution must pass under `-race`
