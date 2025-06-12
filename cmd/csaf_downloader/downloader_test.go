// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package csaf_downloader

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/gocsaf/csaf/v3/internal/testutil"
	"github.com/gocsaf/csaf/v3/pkg/options"
	"github.com/gocsaf/csaf/v3/util"
	"github.com/stretchr/testify/assert"
)

func checkIfFileExists(path string, t *testing.T) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Failed to check if file exists: %v", err)
	}
	return false
}

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name              string
		directoryProvider bool
		wantSha256        bool
		wantSha512        bool
		enableSha256      bool
		enableSha512      bool
		preferredHash     hashAlgorithm
	}{
		{
			name:              "want sha256 and sha512",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
		},
		{
			name:              "only want sha256",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        false,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha256,
		},
		{
			name:              "only want sha512",
			directoryProvider: false,
			wantSha256:        false,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha512,
		},
		{
			name:              "only want sha512",
			directoryProvider: false,
			wantSha256:        false,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha512,
		},

		{
			name:              "only deliver sha256",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        false,
			enableSha256:      true,
			enableSha512:      false,
			preferredHash:     algSha512,
		},
		{
			name:              "only want sha256, directory provider",
			directoryProvider: true,
			wantSha256:        true,
			wantSha512:        false,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha256,
		},
		{
			name:              "only want sha512, directory provider",
			directoryProvider: true,
			wantSha256:        false,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha512,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			params := testutil.ProviderParams{
				URL:          "",
				EnableSha256: test.enableSha256,
				EnableSha512: test.enableSha512,
			}
			server := httptest.NewTLSServer(testutil.ProviderHandler(&params, test.directoryProvider))
			defer server.Close()

			serverURL = server.URL
			params.URL = server.URL

			hClient := server.Client()
			client := util.Client(hClient)

			tempDir := t.TempDir()
			cfg := Config{LogLevel: &options.LogLevel{Level: slog.LevelDebug}, Directory: tempDir, PreferredHash: test.preferredHash}
			err := cfg.Prepare()
			if err != nil {
				t.Fatalf("SHA marking config failed: %v", err)
			}
			d, err := NewDownloader(&cfg)
			if err != nil {
				t.Fatalf("could not init downloader: %v", err)
			}
			d.client = &client

			ctx := context.Background()
			err = d.Run(ctx, []string{serverURL + "/provider-metadata.json"})
			if err != nil {
				t.Errorf("SHA marking %v: Expected no error, got: %v", test.name, err)
			}
			d.Close()

			// Check for downloaded hashes
			sha256Exists := checkIfFileExists(tempDir+"/white/2020/avendor-advisory-0004.json.sha256", t)
			sha512Exists := checkIfFileExists(tempDir+"/white/2020/avendor-advisory-0004.json.sha512", t)

			if sha256Exists != test.wantSha256 {
				t.Errorf("%v: expected sha256 hash present to be %v, got: %v", test.name, test.wantSha256, sha256Exists)
			}

			if sha512Exists != test.wantSha512 {
				t.Errorf("%v: expected sha512 hash present to be %v, got: %v", test.name, test.wantSha512, sha512Exists)
			}
		})
	}
}

func toPtr[T any](v T) *T {
	return &v
}

func TestProxyFromEnvironment(t *testing.T) {
	tests := map[string]struct {
		httpProxy        string
		httpsProxy       string
		csafDLHTTPProxy  *string
		csafDLHTTPSProxy *string
		wantHTTPProxy    string
		wantHTTPSProxy   string
	}{
		"custom http proxy env vars take precedence": {
			httpProxy:        "http://example.com:8080",
			httpsProxy:       "https://example.com:8443",
			csafDLHTTPProxy:  toPtr("http://custom.com:8080"),
			csafDLHTTPSProxy: toPtr("https://custom.com:8443"),
			wantHTTPProxy:    "custom.com:8080",
			wantHTTPSProxy:   "custom.com:8443",
		},
		"common http proxy env vars are still applied if custom env vars are set to empty string": {
			httpProxy:        "http://example.com:8080",
			httpsProxy:       "https://example.com:8443",
			csafDLHTTPProxy:  toPtr(""),
			csafDLHTTPSProxy: toPtr(""),
			wantHTTPProxy:    "example.com:8080",
			wantHTTPSProxy:   "example.com:8443",
		},
		"common http proxy env vars are still applied if custom env vars are unset": {
			httpProxy:        "http://example.com:8080",
			httpsProxy:       "https://example.com:8443",
			csafDLHTTPProxy:  nil,
			csafDLHTTPSProxy: nil,
			wantHTTPProxy:    "example.com:8080",
			wantHTTPSProxy:   "example.com:8443",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("http_proxy", tt.httpProxy)
			t.Setenv("https_proxy", tt.httpsProxy)
			if tt.csafDLHTTPProxy != nil {
				t.Setenv("CSAF_DL_HTTP_PROXY", *tt.csafDLHTTPProxy)
			}
			if tt.csafDLHTTPSProxy != nil {
				t.Setenv("CSAF_DL_HTTPS_PROXY", *tt.csafDLHTTPSProxy)
			}

			getProxyURL := func(targetURL string) (url.URL, error) {
				req := httptest.NewRequest("GET", targetURL, nil)
				proxyURL, err := proxyFromEnvironment(req)
				if proxyURL == nil {
					proxyURL = &url.URL{} // it us cumbersome to check for nil later
				}
				return *proxyURL, err
			}

			proxyURL, err := getProxyURL("http://target.com")
			assert.NoError(t, err)
			assert.Equal(t, tt.wantHTTPProxy, proxyURL.Host, "http proxy mismatch")

			// same checks for https
			proxyURL, err = getProxyURL("https://target.com")
			assert.NoError(t, err)
			assert.Equal(t, tt.wantHTTPSProxy, proxyURL.Host, "https proxy mismatch")
		})
	}
}
