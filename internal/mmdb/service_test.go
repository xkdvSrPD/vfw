package mmdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"vfw/internal/envcfg"
	"vfw/internal/model"
)

func TestResolveRulesWithoutMMDB(t *testing.T) {
	t.Parallel()

	service := NewService(envcfg.Config{})
	rules := []model.Rule{
		{
			Port:      22,
			Source:    model.Source{Type: model.SourceAll},
			Protocols: []model.Protocol{model.ProtocolTCP},
		},
		{
			Port:      53,
			Source:    model.Source{Type: model.SourceIP, Values: []string{"1.1.1.1/32", "10.0.0.0/8"}},
			Protocols: []model.Protocol{model.ProtocolUDP},
		},
	}
	for index := range rules {
		if err := rules[index].EnsureDefaults(); err != nil {
			t.Fatalf("EnsureDefaults(%d) returned error: %v", index, err)
		}
	}

	resolved, err := service.ResolveRules(context.Background(), rules)
	if err != nil {
		t.Fatalf("ResolveRules returned error: %v", err)
	}
	if len(resolved[rules[0].SetName]) != 0 {
		t.Fatalf("unexpected all-source resolution: %#v", resolved[rules[0].SetName])
	}
	if len(resolved[rules[1].SetName]) != 2 {
		t.Fatalf("unexpected IP-source resolution: %#v", resolved[rules[1].SetName])
	}
}

func TestInspect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		prepare     func(t *testing.T, cfg envcfg.Config)
		wantMissing []string
		wantRefresh bool
	}{
		{
			name:        "missing files need refresh",
			prepare:     func(t *testing.T, cfg envcfg.Config) {},
			wantMissing: []string{"ASN", "Country", "City"},
			wantRefresh: true,
		},
		{
			name: "fresh files are current",
			prepare: func(t *testing.T, cfg envcfg.Config) {
				writeMMDBFiles(t, cfg, time.Now().UTC())
			},
			wantRefresh: false,
		},
		{
			name: "stale files need refresh",
			prepare: func(t *testing.T, cfg envcfg.Config) {
				writeMMDBFiles(t, cfg, time.Now().UTC().Add(-48*time.Hour))
			},
			wantRefresh: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := envcfg.Config{DataDir: t.TempDir()}
			test.prepare(t, cfg)

			status, err := NewService(cfg).Inspect(1)
			if err != nil {
				t.Fatalf("Inspect returned error: %v", err)
			}
			if got, want := strings.Join(status.Missing, ","), strings.Join(test.wantMissing, ","); got != want {
				t.Fatalf("missing mismatch: got %q want %q", got, want)
			}
			if status.NeedsRefresh != test.wantRefresh {
				t.Fatalf("NeedsRefresh mismatch: got %v want %v", status.NeedsRefresh, test.wantRefresh)
			}
		})
	}
}

func TestEnsureCurrentDownloadsMissingFilesUsingEnvURLs(t *testing.T) {
	dataDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(strings.TrimPrefix(request.URL.Path, "/")))
	}))
	defer server.Close()

	t.Setenv("VFW_GEOIP_ASN_URL", server.URL+"/asn")
	t.Setenv("VFW_GEOIP_COUNTRY_URL", server.URL+"/country")
	t.Setenv("VFW_GEOIP_CITY_URL", server.URL+"/city")

	service := NewService(envcfg.Config{DataDir: dataDir})
	downloaded, err := service.EnsureCurrent(context.Background(), 1, false)
	if err != nil {
		t.Fatalf("EnsureCurrent returned error: %v", err)
	}
	if !downloaded {
		t.Fatal("EnsureCurrent should download missing files")
	}

	checks := []struct {
		path string
		want string
	}{
		{path: service.cfg.ASNDBPath(), want: "asn"},
		{path: service.cfg.CountryDBPath(), want: "country"},
		{path: service.cfg.CityDBPath(), want: "city"},
	}
	for _, check := range checks {
		buffer, err := os.ReadFile(check.path)
		if err != nil {
			t.Fatalf("ReadFile(%s) returned error: %v", check.path, err)
		}
		if got := string(buffer); got != check.want {
			t.Fatalf("downloaded content mismatch for %s: got %q want %q", check.path, got, check.want)
		}
	}
}

func TestNormalizeCityValue(t *testing.T) {
	t.Parallel()

	if got, want := normalizeCityValue("  ShangHai "), "shanghai"; got != want {
		t.Fatalf("normalizeCityValue mismatch: got %q want %q", got, want)
	}
}

func writeMMDBFiles(t *testing.T, cfg envcfg.Config, modifiedAt time.Time) {
	t.Helper()

	for _, path := range []string{cfg.ASNDBPath(), cfg.CountryDBPath(), cfg.CityDBPath()} {
		if err := os.WriteFile(path, []byte("dummy"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) returned error: %v", path, err)
		}
		if err := os.Chtimes(path, modifiedAt, modifiedAt); err != nil {
			t.Fatalf("Chtimes(%s) returned error: %v", path, err)
		}
	}
}
