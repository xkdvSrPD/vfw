// Package mmdb downloads GeoLite databases and resolves selectors to IPv4 prefixes.
package mmdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"

	"vfw/internal/envcfg"
	"vfw/internal/model"
)

// DatabaseStatus reports whether the managed mmdb files are present and fresh enough to use.
type DatabaseStatus struct {
	Missing      []string
	NeedsRefresh bool
}

// Service resolves vfw rules through local mmdb files.
type Service struct {
	cfg    envcfg.Config
	client *http.Client
}

// NewService constructs a mmdb service with a conservative HTTP timeout.
func NewService(cfg envcfg.Config) *Service {
	return &Service{
		cfg: cfg,
		client: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

// Inspect reports whether the managed mmdb files are missing or older than the configured refresh interval.
func (s *Service) Inspect(refreshDays int) (DatabaseStatus, error) {
	if refreshDays < 1 {
		refreshDays = 1
	}
	status := DatabaseStatus{}
	var oldestModTime time.Time
	for _, file := range s.databaseFiles() {
		info, err := os.Stat(file.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			status.Missing = append(status.Missing, file.Name)
			continue
		case err != nil:
			return DatabaseStatus{}, fmt.Errorf("stat mmdb %s: %w", file.Path, err)
		}
		modTime := info.ModTime().UTC()
		if oldestModTime.IsZero() || modTime.Before(oldestModTime) {
			oldestModTime = modTime
		}
	}
	if len(status.Missing) > 0 {
		status.NeedsRefresh = true
		return status, nil
	}
	status.NeedsRefresh = time.Since(oldestModTime) >= time.Duration(refreshDays)*24*time.Hour
	return status, nil
}

// EnsureDatabases downloads missing mmdb files when requested.
func (s *Service) EnsureDatabases(ctx context.Context, downloadIfMissing bool) error {
	missing := s.missingPaths()
	if len(missing) == 0 {
		return nil
	}
	if !downloadIfMissing {
		return fmt.Errorf("missing mmdb files: %s", strings.Join(missing, ", "))
	}
	return s.DownloadDatabases(ctx)
}

// EnsureCurrent refreshes the managed mmdb files when they are missing, stale, or force is true.
func (s *Service) EnsureCurrent(ctx context.Context, refreshDays int, force bool) (bool, error) {
	status, err := s.Inspect(refreshDays)
	if err != nil {
		return false, err
	}
	if !force && !status.NeedsRefresh {
		return false, nil
	}
	if err := s.DownloadDatabases(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// DownloadDatabases refreshes all bundled mmdb files.
func (s *Service) DownloadDatabases(ctx context.Context) error {
	if err := os.MkdirAll(s.cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	type downloadTask struct {
		url  string
		path string
	}
	urls := envcfg.LoadGeoIPURLs()
	tasks := []downloadTask{
		{url: urls.ASN, path: s.cfg.ASNDBPath()},
		{url: urls.Country, path: s.cfg.CountryDBPath()},
		{url: urls.City, path: s.cfg.CityDBPath()},
	}

	errCh := make(chan error, len(tasks))
	var waitGroup sync.WaitGroup
	for _, task := range tasks {
		task := task
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if err := s.downloadFile(ctx, task.url, task.path); err != nil {
				errCh <- err
			}
		}()
	}
	waitGroup.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// ResolveRules resolves each rule to the final IPv4 prefixes that should populate its ipset.
func (s *Service) ResolveRules(ctx context.Context, rules []model.Rule) (map[string][]string, error) {
	results := make(map[string]map[string]struct{}, len(rules))
	asnTargets := make(map[uint][]string)
	countryTargets := make(map[string][]string)
	cityTargets := make(map[string][]string)
	mmdbRuleSets := make(map[string]model.Rule)

	for _, rule := range rules {
		ruleCopy := rule
		results[rule.SetName] = make(map[string]struct{})
		switch rule.Source.Type {
		case model.SourceAll:
			// Allow-all rules are handled directly in iptables and keep an empty ipset.
		case model.SourceIP:
			for _, value := range rule.Source.Values {
				results[rule.SetName][value] = struct{}{}
			}
		case model.SourceASN:
			mmdbRuleSets[rule.SetName] = ruleCopy
			for _, value := range rule.Source.Values {
				asn, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid ASN %q in %s", value, rule.CanonicalCommand())
				}
				asnTargets[uint(asn)] = append(asnTargets[uint(asn)], rule.SetName)
			}
		case model.SourceCountry:
			mmdbRuleSets[rule.SetName] = ruleCopy
			for _, value := range rule.Source.Values {
				countryTargets[strings.ToUpper(value)] = append(countryTargets[strings.ToUpper(value)], rule.SetName)
			}
		case model.SourceCity:
			mmdbRuleSets[rule.SetName] = ruleCopy
			for _, value := range rule.Source.Values {
				normalized := normalizeCityValue(value)
				cityTargets[normalized] = append(cityTargets[normalized], rule.SetName)
			}
		default:
			return nil, fmt.Errorf("unsupported source type %q", rule.Source.Type)
		}
	}

	if len(asnTargets) > 0 {
		if err := s.scanASN(ctx, asnTargets, results); err != nil {
			return nil, err
		}
	}
	if len(countryTargets) > 0 {
		if err := s.scanCountry(ctx, countryTargets, results); err != nil {
			return nil, err
		}
	}
	if len(cityTargets) > 0 {
		if err := s.scanCity(ctx, cityTargets, results); err != nil {
			return nil, err
		}
	}

	final := make(map[string][]string, len(results))
	for setName, entrySet := range results {
		if rule, ok := mmdbRuleSets[setName]; ok && len(entrySet) == 0 {
			return nil, fmt.Errorf("rule %q resolved to zero IPv4 prefixes", rule.CanonicalCommand())
		}
		entries := make([]string, 0, len(entrySet))
		for value := range entrySet {
			entries = append(entries, value)
		}
		sort.Strings(entries)
		final[setName] = entries
	}
	return final, nil
}

func (s *Service) downloadFile(ctx context.Context, url string, path string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request for %s: %w", url, err)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: unexpected status %s", url, response.Status)
	}

	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	if _, err := io.Copy(file, response.Body); err != nil {
		file.Close()
		return fmt.Errorf("write temp file for %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func (s *Service) scanASN(ctx context.Context, targets map[uint][]string, results map[string]map[string]struct{}) error {
	type asnRecord struct {
		ASN uint `maxminddb:"autonomous_system_number"`
	}
	return s.scan(ctx, s.cfg.ASNDBPath(), func(prefix netip.Prefix, result maxminddb.Result) error {
		var record asnRecord
		if err := result.Decode(&record); err != nil {
			return err
		}
		for _, setName := range targets[record.ASN] {
			results[setName][prefix.String()] = struct{}{}
		}
		return nil
	})
}

func (s *Service) scanCountry(ctx context.Context, targets map[string][]string, results map[string]map[string]struct{}) error {
	type countryRecord struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	return s.scan(ctx, s.cfg.CountryDBPath(), func(prefix netip.Prefix, result maxminddb.Result) error {
		var record countryRecord
		if err := result.Decode(&record); err != nil {
			return err
		}
		for _, setName := range targets[strings.ToUpper(record.Country.ISOCode)] {
			results[setName][prefix.String()] = struct{}{}
		}
		return nil
	})
}

func (s *Service) scanCity(ctx context.Context, targets map[string][]string, results map[string]map[string]struct{}) error {
	type cityRecord struct {
		City struct {
			GeoNameID uint              `maxminddb:"geoname_id"`
			Names     map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
	}
	return s.scan(ctx, s.cfg.CityDBPath(), func(prefix netip.Prefix, result maxminddb.Result) error {
		var record cityRecord
		if err := result.Decode(&record); err != nil {
			return err
		}
		candidates := []string{
			strconv.FormatUint(uint64(record.City.GeoNameID), 10),
			normalizeCityValue(record.City.Names["en"]),
		}
		for _, candidate := range candidates {
			if candidate == "" {
				continue
			}
			for _, setName := range targets[candidate] {
				results[setName][prefix.String()] = struct{}{}
			}
		}
		return nil
	})
}

func (s *Service) scan(ctx context.Context, path string, consume func(netip.Prefix, maxminddb.Result) error) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("open mmdb %s: %w", path, err)
	}
	defer db.Close()

	for result := range db.Networks() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := result.Err(); err != nil {
			return fmt.Errorf("iterate %s: %w", filepath.Base(path), err)
		}
		prefix := result.Prefix()
		if !prefix.Addr().Is4() {
			continue
		}
		if err := consume(prefix, result); err != nil {
			return fmt.Errorf("decode %s record %s: %w", filepath.Base(path), prefix.String(), err)
		}
	}
	return nil
}

func (s *Service) missingPaths() []string {
	files := s.databaseFiles()
	var missing []string
	for _, file := range files {
		if _, err := os.Stat(file.Path); err != nil {
			missing = append(missing, file.Path)
		}
	}
	return missing
}

type databaseFile struct {
	Name string
	Path string
}

func (s *Service) databaseFiles() []databaseFile {
	return []databaseFile{
		{Name: "ASN", Path: s.cfg.ASNDBPath()},
		{Name: "Country", Path: s.cfg.CountryDBPath()},
		{Name: "City", Path: s.cfg.CityDBPath()},
	}
}

func normalizeCityValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
