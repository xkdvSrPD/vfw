# AGENTS.md

## Project Scope

- `vfw` is a firewall CLI for Ubuntu and Debian built on top of `iptables` and `ipset`.
- Runtime support is Linux IPv4 only.
- Persistent rules live in `/etc/vfw/rules.json`.
- Refresh logs are written to `/var/log/vfw/vfw.log`.
- Linux `ipset` names are limited to 31 characters. The persisted config is the source of truth for full rule meaning. Do not derive long rules from `ipset` names.

## Repository Map

- `cmd/vfw`: CLI entrypoint.
- `internal/app`: command orchestration and status output.
- `internal/firewall`: `iptables` and `ipset` operations.
- `internal/mmdb`: GeoLite mmdb download, load, and refresh logic.
- `internal/parser`, `internal/model`: CLI parsing and rule modeling.
- `packaging/deb`: deb package layout, cron files, defaults, and maintainer scripts.
- `scripts/build-deb.sh`: build a `.deb` package.
- `scripts/publish-release.sh`: publish an artifact to a Gitea release.

## Development Constraints

- Target Go version is `1.24.0`.
- Module path is `vfw`.
- Firewall changes must stay idempotent and must not lock out the current SSH session.
- When changing packaging or release behavior, treat `.gitea/workflows/*.yml` as the primary automation because `origin` points to Gitea. Also check whether `.github/workflows/release.yml` must stay in sync.
- `scripts/build-deb.sh` requires Linux tools such as `bash` and `dpkg-deb`. If the local machine is not suitable, use WSL, CI, or the remote host `p`.

## Common Commands

```bash
go test ./...
CGO_ENABLED=1 go test -race ./...
make build
make test
make deb VERSION=0.1.0 ARCH=amd64
```

Notes:

- `make build` writes `dist/vfw`.
- `make deb` writes `dist/vfw_<version>_<arch>.deb`.
- Version and commit metadata are injected through linker flags and exposed by `vfw version`.

## Testing Expectations

- Any behavior change should add or update at least one `_test.go`.
- Parser or rule-model changes should usually add coverage under `internal/parser` or `internal/model`.
- Firewall or reload behavior changes should usually extend `internal/firewall/manager_test.go`.
- MMDB or refresh behavior changes should usually extend `internal/mmdb/service_test.go`.
- Changes involving concurrency, external command execution, or state recovery should run both `go test ./...` and `CGO_ENABLED=1 go test -race ./...`.

## Remote Test Host

- This repository may use the SSH host alias `p` from the local SSH config as the Debian or Ubuntu test machine.
- Confirm `ssh p` works before using it in validation steps.
- Never run `vfw enable` on `p` unless the SSH port is already allowed.
- If local deb packaging is not available, build in a Linux environment first or sync the repo to `p` and test there.

Recommended smoke test:

```bash
make deb VERSION=0.1.0 ARCH=amd64
scp dist/vfw_0.1.0_amd64.deb p:/tmp/
ssh p 'sudo apt-get update && sudo apt-get install -y iptables ipset'
ssh p 'sudo apt install -y /tmp/vfw_0.1.0_amd64.deb'
ssh p 'vfw version && sudo vfw status'
ssh p 'sudo vfw allow 22'
ssh p 'sudo vfw reload && sudo vfw ls'
ssh p 'sudo iptables -S | grep VFW || true'
ssh p 'sudo ipset list | head'
```

Additional rules:

- If `vfw enable` or `vfw disable` must be tested, keep an existing SSH session open for recovery.
- If the initial mmdb download fails after install, retry with `sudo vfw refresh --force`.
- Clean up temporary rules and packages after remote validation.

## Commit Conventions

- Keep each commit focused on one logical change.
- Use short imperative English commit subjects.
- Preferred format is Conventional Commits: `type(scope): summary`.
- Recommended types: `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`, `revert`.
- Keep the subject line within 72 characters when practical.
- If the change affects release behavior, packaging, firewall semantics, or rollback risk, explain validation and rollback notes in the commit body.

Examples:

```text
feat(parser): support mixed country selectors
fix(firewall): preserve existing ipset members on reload
docs: document remote smoke test flow
```

## Release Process

1. Before merging to `main`, run at least `go test ./...`.
2. If the change touches concurrency or external command execution, also run `CGO_ENABLED=1 go test -race ./...`.
3. Build the release artifact with `make deb VERSION=X.Y.Z ARCH=amd64`.
4. Run an install or upgrade smoke test on `p`. At minimum verify `vfw version`, `vfw status`, `vfw allow 22`, `vfw reload`, and `vfw ls`. Run `vfw refresh --force` when the change affects mmdb refresh behavior.
5. Tag the release commit on `main` with a semantic version tag such as `vX.Y.Z`.
6. Push code and tags with `git push origin main --tags`.
7. The primary Gitea release pipeline is `.gitea/workflows/release.yml`. It reruns tests, builds the `.deb`, and uploads it through `scripts/publish-release.sh`.
8. If a release asset must be republished manually, use `scripts/publish-release.sh` with `GITEA_API_URL`, `GITEA_REPOSITORY`, `GITEA_TOKEN`, `TAG_NAME`, and `ARTIFACT_PATH`.

## Pre-merge Checklist

- Unit tests passed.
- Race test ran when needed.
- Packaging and workflow changes stayed in sync.
- Remote smoke test on `p` was completed or explicitly skipped with a reason.
- README or release docs were updated when behavior changed.
