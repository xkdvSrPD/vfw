# vfw

`vfw` is a small Ubuntu/Debian firewall CLI inspired by `ufw`, focused on port protection driven by `iptables` and `ipset`.

## What It Does

- Stores rules in `/etc/vfw/rules.json`
- Uses a dedicated `iptables` chain to avoid colliding with Docker or other tooling
- Creates one `ipset` per user-added rule
- Resolves `asn`, `country`, and `city` selectors from bundled GeoLite mmdb files
- Applies saved config during `enable`, `reload`, and `refresh`
- Downloads mmdb files on demand when they are missing or outdated
- Logs refresh activity to `/var/log/vfw/vfw.log`

## Supported Environment

- Ubuntu or Debian only
- `iptables` and `ipset` must already be installed
- IPv4 only in the current implementation
- No daemon; everything runs as one-shot shell commands

## Command Examples

```bash
vfw allow 22
vfw allow 443 from country CN,US tcp
vfw allow 53 from asn 4134,4837 udp
vfw allow 3306 from city 1796236 tcp
vfw allow 8080 from 1.1.1.1,10.0.0.0/8 tcp

vfw ls
vfw status
vfw version
vfw delete 2
vfw enable
vfw disable
vfw reload
vfw refresh --force
```

`vfw allow` and `vfw delete` only update `/etc/vfw/rules.json`. Runtime firewall and `ipset` changes are applied when you run `vfw enable`, `vfw reload`, or `vfw refresh`.

## Selector Notes

- `asn`: numeric ASN list, comma-separated
- `country`: 2-letter ISO country codes
- `city`: GeoName ID or English city name from the city mmdb
- direct IP selectors accept IPv4 address or CIDR values

## Refresh Model

- Default refresh interval is `1` day
- Override with `VFW_REFRESH_DAYS`
- Package install does not download mmdb files
- Package cron runs `vfw refresh` hourly; the binary refreshes mmdb files only when they are missing or older than the configured interval
- `vfw enable` and `vfw reload` also perform the same on-demand mmdb freshness check before applying rules
- `vfw refresh --force` bypasses the interval check

## Environment Overrides

```bash
export VFW_CONFIG_DIR=/etc/vfw
export VFW_LOG_DIR=/var/log/vfw
export VFW_DATA_DIR=/usr/local/bin
export VFW_REFRESH_DAYS=1
export VFW_GEOIP_ASN_URL=https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
export VFW_GEOIP_COUNTRY_URL=https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
export VFW_GEOIP_CITY_URL=https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
```

## Packaging

```bash
make test
make deb VERSION=0.1.0 ARCH=amd64
```

The generated package is written to `dist/` and installs the binary to `/usr/local/bin/vfw`.
The package does not fetch mmdb files during `apt install`; the first `vfw enable`, `vfw reload`, or `vfw refresh` downloads them when needed.

## Release Flow

- Push regular commits to `main` to run test and package validation
- Push a semantic tag like `v0.1.0` to create a Gitea Release and upload the `.deb` artifact
- `vfw version` prints the injected version and git revision from the build pipeline

## Important Constraint

Linux `ipset` names are limited to 31 characters. Because of that kernel limit, `vfw` stores the full canonical command in `/etc/vfw/rules.json` and uses a deterministic short `ipset` name derived from the rule. Listing rules is based on persisted config, not on reconstructing long commands from the kernel object name alone.
