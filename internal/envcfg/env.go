// Package envcfg loads runtime paths and environment-based overrides.
package envcfg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultASNURL is the fallback download URL for the ASN database.
	DefaultASNURL = "https://git.vio.vin/violet/GeoLite2-City/raw/branch/main/GeoLite2-ASN.mmdb"
	// DefaultCountryURL is the fallback download URL for the country database.
	DefaultCountryURL = "https://git.vio.vin/violet/GeoLite2-City/raw/branch/main/GeoLite2-Country.mmdb"
	// DefaultCityURL is the fallback download URL for the city database.
	DefaultCityURL = "https://git.vio.vin/violet/GeoLite2-City/raw/branch/main/GeoLite2-City.mmdb"
)

const (
	asnFileName     = "GeoLite2-ASN.mmdb"
	countryFileName = "GeoLite2-Country.mmdb"
	cityFileName    = "GeoLite2-City.mmdb"
)

// Config contains every runtime path and external binary used by vfw.
type Config struct {
	ConfigDir      string
	LogDir         string
	DataDir        string
	ASNURL         string
	CountryURL     string
	CityURL        string
	RefreshDays    int
	IPTablesBinary string
	IPSetBinary    string
}

// Load reads environment variables and resolves runtime defaults.
func Load() (Config, error) {
	exePath, err := os.Executable()
	if err != nil {
		return Config{}, fmt.Errorf("resolve executable path: %w", err)
	}
	dataDir := filepath.Dir(exePath)
	refreshDays := envInt("VFW_REFRESH_DAYS", 1)
	if refreshDays < 1 {
		refreshDays = 1
	}
	return Config{
		ConfigDir:      envString("VFW_CONFIG_DIR", "/etc/vfw"),
		LogDir:         envString("VFW_LOG_DIR", "/var/log/vfw"),
		DataDir:        envString("VFW_DATA_DIR", dataDir),
		ASNURL:         envString("VFW_GEOIP_ASN_URL", DefaultASNURL),
		CountryURL:     envString("VFW_GEOIP_COUNTRY_URL", DefaultCountryURL),
		CityURL:        envString("VFW_GEOIP_CITY_URL", DefaultCityURL),
		RefreshDays:    refreshDays,
		IPTablesBinary: envString("VFW_IPTABLES_BIN", "iptables"),
		IPSetBinary:    envString("VFW_IPSET_BIN", "ipset"),
	}, nil
}

// ASNDBPath returns the on-disk location of the ASN mmdb file.
func (c Config) ASNDBPath() string {
	return filepath.Join(c.DataDir, asnFileName)
}

// CountryDBPath returns the on-disk location of the country mmdb file.
func (c Config) CountryDBPath() string {
	return filepath.Join(c.DataDir, countryFileName)
}

// CityDBPath returns the on-disk location of the city mmdb file.
func (c Config) CityDBPath() string {
	return filepath.Join(c.DataDir, cityFileName)
}

// LogPath returns the main application log file path.
func (c Config) LogPath() string {
	return filepath.Join(c.LogDir, "vfw.log")
}

// AppendLog appends a timestamped line to the vfw log file.
func AppendLog(ctx context.Context, cfg Config, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	file, err := os.OpenFile(cfg.LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer file.Close()

	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339), strings.TrimSpace(message))
	if _, err := file.WriteString(line); err != nil {
		return fmt.Errorf("write log file: %w", err)
	}
	return nil
}

func envString(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
