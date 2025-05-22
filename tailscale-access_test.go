package tailscale_access_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hhftechnology/tailscale-access" // Adjust import path if your module name is different
)

func TestTailscaleAuth(t *testing.T) {
	// Common handler for successful requests
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	// Test cases
	testCases := []struct {
		name               string
		config             *tailscaleauth.Config
		remoteAddr         string
		headers            map[string]string
		expectedStatusCode int
		expectedBody       string // If non-empty, check for this substring in the body
		expectAllow        bool
	}{
		{
			name:               "Allow Tailscale IP in RemoteAddr",
			config:             tailscaleauth.CreateConfig(), // Uses default Tailscale range 100.64.0.0/10
			remoteAddr:         "100.64.1.100:12345",
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name:               "Block non-Tailscale IP in RemoteAddr",
			config:             tailscaleauth.CreateConfig(),
			remoteAddr:         "192.168.1.100:12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       tailscaleauth.DefaultErrorMessage,
			expectAllow:        false,
		},
		{
			name: "Allow Tailscale IP in X-Forwarded-For header",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
			},
			remoteAddr:         "1.2.3.4:12345", // Non-Tailscale direct IP
			headers:            map[string]string{"X-Forwarded-For": "100.65.0.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Allow Tailscale IP (first) in X-Forwarded-For list",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "100.70.0.1, 192.168.0.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Block non-Tailscale IP (first) in X-Forwarded-For list, Tailscale IP later",
			config: &tailscaleauth.Config{ // Default behavior is to take the first IP from the first matched header
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "192.168.0.1, 100.70.0.1"},
			expectedStatusCode: http.StatusForbidden, // Because 192.168.0.1 is checked first from XFF
			expectAllow:        false,
		},
		{
			name: "Allow Tailscale IP in X-Real-IP header",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Real-IP", "X-Forwarded-For"},
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Real-IP": "100.100.100.100"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Allow AdditionalRange IP in RemoteAddr",
			config: &tailscaleauth.Config{
				TailscaleRanges:  []string{"100.64.0.0/10"},
				AdditionalRanges: []string{"127.0.0.1/32", "192.168.5.0/24"},
			},
			remoteAddr:         "192.168.5.10:54321",
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Allow AdditionalRange IP in X-Forwarded-For",
			config: &tailscaleauth.Config{
				TailscaleRanges:  []string{"100.64.0.0/10"},
				AdditionalRanges: []string{"127.0.0.1/32"},
				HeadersToCheck:   []string{"X-Forwarded-For"},
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "127.0.0.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Block with custom error message",
			config: &tailscaleauth.Config{
				TailscaleRanges:    []string{"100.64.0.0/10"},
				CustomErrorMessage: "Tailscale only, buddy!",
			},
			remoteAddr:         "8.8.8.8:12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       "Tailscale only, buddy!",
			expectAllow:        false,
		},
		{
			name: "Debug logging enabled (coverage)",
			config: &tailscaleauth.Config{
				TailscaleRanges:    []string{"100.64.0.0/10"},
				EnableDebugLogging: true,
			},
			remoteAddr:         "100.64.1.1:12345", // Allowed
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name:               "No valid IP (empty RemoteAddr, no headers)",
			config:             tailscaleauth.CreateConfig(),
			remoteAddr:         "", // Invalid or empty
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectAllow:        false,
		},
		{
			name:               "Invalid RemoteAddr format (no port)",
			config:             tailscaleauth.CreateConfig(),
			remoteAddr:         "100.64.1.1", // Allowed if treated as IP
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Block if RemoteAddr is just a port",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
			},
			remoteAddr:         ":12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectAllow:        false,
		},
		{
			name: "Allow if only AdditionalRanges configured and IP matches",
			config: &tailscaleauth.Config{
				TailscaleRanges:  []string{}, // No Tailscale ranges
				AdditionalRanges: []string{"192.168.7.0/24"},
			},
			remoteAddr:         "192.168.7.7:12345",
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Block if only AdditionalRanges configured and IP does not match",
			config: &tailscaleauth.Config{
				TailscaleRanges:  []string{},
				AdditionalRanges: []string{"192.168.7.0/24"},
			},
			remoteAddr:         "10.0.0.1:12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectAllow:        false,
		},
		{
			name: "Empty HeadersToCheck, fallback to RemoteAddr (allow)",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{}, // Will use default in New if not set, but test explicit empty
			},
			remoteAddr:         "100.64.2.2:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8"}, // This header should be ignored
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Empty HeadersToCheck, fallback to RemoteAddr (block)",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{},
			},
			remoteAddr:         "8.8.8.8:12345",
			headers:            map[string]string{"X-Forwarded-For": "100.64.2.2"}, // This header should be ignored
			expectedStatusCode: http.StatusForbidden,
			expectAllow:        false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Ensure CreateConfig defaults are handled if config is minimal
			if tc.config.CustomErrorMessage == "" && !tc.expectAllow {
				tc.config.CustomErrorMessage = tailscaleauth.DefaultErrorMessage
			}
			if len(tc.config.TailscaleRanges) == 0 && len(tc.config.AdditionalRanges) == 0 {
				// If test case implies default Tailscale range should be used
				if strings.Contains(tc.name, "Tailscale IP") || tc.expectAllow {
					// This might need adjustment based on whether the test intends to use defaults or truly empty ranges
					// For now, assume if it's a Tailscale test, it needs the default range.
					// A better approach might be to have CreateConfig() called explicitly in test case if defaults are desired.
					// Or, ensure New() correctly applies defaults.
				}
			}


			handler, err := tailscaleauth.New(ctx, nextHandler, tc.config, "test-"+tc.name)
			if err != nil {
				// If we expect an error during New (e.g. bad CIDR), handle it here.
				// For now, assuming valid configs for New.
				t.Fatalf("tailscaleauth.New() error = %v", err)
				return
			}

			recorder := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedStatusCode, recorder.Code)
			}

			if tc.expectedBody != "" {
				bodyBytes, _ := io.ReadAll(recorder.Body)
				bodyString := string(bodyBytes)
				if !strings.Contains(bodyString, tc.expectedBody) {
					t.Errorf("Expected body to contain %q, got %q", tc.expectedBody, bodyString)
				}
			}
		})
	}
}

func TestNew_ErrorCases(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	ctx := context.Background()

	testCases := []struct {
		name        string
		config      *tailscaleauth.Config
		expectedErr string
	}{
		{
			name: "Invalid Tailscale CIDR",
			config: &tailscaleauth.Config{
				TailscaleRanges: []string{"100.64.0.0/invalid"},
			},
			expectedErr: "invalid CIDR string",
		},
		{
			name: "Invalid Additional CIDR",
			config: &tailscaleauth.Config{
				AdditionalRanges: []string{"192.168.1.0/foo"},
			},
			expectedErr: "invalid CIDR string",
		},
		{
			name: "No ranges configured (after defaults)",
			config: &tailscaleauth.Config{
				TailscaleRanges:  []string{""}, // Empty string should be skipped, leading to no valid ranges
				AdditionalRanges: []string{""},
			},
			// This test case needs careful handling of how New applies defaults.
			// If New sets default TailscaleRanges if empty, this won't error.
			// The current New logic *does* set default TailscaleRanges if config.TailscaleRanges is empty.
			// To test "no ranges", we'd need to ensure the config passed to New has empty *after* any internal defaulting logic.
			// For now, let's assume the goal is to test if *all* provided ranges are invalid or empty.
			// The error "at least one valid TailscaleRange or AdditionalRange must be provided"
			expectedErr: "at least one valid TailscaleRange or AdditionalRange must be provided",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// If the test config is designed to use CreateConfig defaults first, do that.
			// Otherwise, use the tc.config directly.
			// For these error cases, we usually provide the problematic config directly.

			// Special handling for "No ranges configured" to ensure defaults are not applied by CreateConfig()
			// if the test intends to pass an effectively empty set of ranges to New().
			var cfgToUse *tailscaleauth.Config
			if tc.name == "No ranges configured (after defaults)" {
				cfgToUse = tc.config // Use the specific config that results in no valid ranges
			} else {
				// For other error cases, we might want to start from defaults and override.
				// However, here we are testing specific invalid parts.
				cfgToUse = tc.config
				// Fill in other parts with defaults if not specified, to isolate the error.
				if cfgToUse.HeadersToCheck == nil {
					cfgToUse.HeadersToCheck = tailscaleauth.DefaultHeadersToCheck
				}
				if cfgToUse.CustomErrorMessage == "" {
					cfgToUse.CustomErrorMessage = tailscaleauth.DefaultErrorMessage
				}
				// If TailscaleRanges is nil (not just empty) and not the part being tested for error,
				// and AdditionalRanges is also nil, New might apply defaults.
				// This part is tricky for error testing. Let's assume tc.config is specific enough.
			}


			_, err := tailscaleauth.New(ctx, nextHandler, cfgToUse, "test-new-error")
			if err == nil {
				t.Fatalf("Expected an error, but got nil")
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("Expected error message to contain %q, got %q", tc.expectedErr, err.Error())
			}
		})
	}
}
