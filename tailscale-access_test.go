package tailscale_access_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tailscale_access "github.com/hhftechnology/tailscale-access"
)

func TestTailscaleAuth_BasicFunctionality(t *testing.T) {
	// Common handler for successful requests
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name               string
		config             *tailscale_access.Config
		remoteAddr         string
		headers            map[string]string
		expectedStatusCode int
		expectedBody       string
		expectAllow        bool
	}{
		{
			name:               "Allow Tailscale IP in RemoteAddr",
			config:             tailscale_access.CreateConfig(),
			remoteAddr:         "100.64.1.100:12345",
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name:               "Block non-Tailscale IP in RemoteAddr",
			config:             tailscale_access.CreateConfig(),
			remoteAddr:         "192.168.1.100:12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       tailscale_access.DefaultErrorMessage,
			expectAllow:        false,
		},
		{
			name: "Allow Tailscale IP in X-Forwarded-For header (strict mode)",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				StrictMode:      true,
			},
			remoteAddr:         "1.2.3.4:12345", // Non-Tailscale direct IP
			headers:            map[string]string{"X-Forwarded-For": "100.65.0.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Block non-Tailscale IP in X-Forwarded-For header (strict mode)",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				StrictMode:      true,
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8"},
			expectedStatusCode: http.StatusForbidden,
			expectAllow:        false,
		},
		{
			name: "Allow first valid IP in non-strict mode",
			config: &tailscale_access.Config{
				TailscaleRanges:  []string{"100.64.0.0/10"},
				AdditionalRanges: []string{"8.8.8.0/24"},
				HeadersToCheck:   []string{"X-Forwarded-For"},
				StrictMode:       false,
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Find Tailscale IP in list (strict mode)",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				StrictMode:      true,
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8, 100.70.0.1, 192.168.1.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Block when no Tailscale IP in list (strict mode)",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				StrictMode:      true,
			},
			remoteAddr:         "1.2.3.4:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8, 192.168.1.1, 10.0.0.1"},
			expectedStatusCode: http.StatusForbidden,
			expectAllow:        false,
		},
		{
			name: "Allow AdditionalRange IP in RemoteAddr",
			config: &tailscale_access.Config{
				TailscaleRanges:  []string{"100.64.0.0/10"},
				AdditionalRanges: []string{"127.0.0.1/32", "192.168.5.0/24"},
			},
			remoteAddr:         "192.168.5.10:54321",
			headers:            nil,
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Custom error message",
			config: &tailscale_access.Config{
				TailscaleRanges:    []string{"100.64.0.0/10"},
				CustomErrorMessage: "Tailscale only, buddy!",
			},
			remoteAddr:         "8.8.8.8:12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       "Tailscale only, buddy!",
			expectAllow:        false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Set defaults if not provided
			if tc.config.CustomErrorMessage == "" && !tc.expectAllow {
				tc.config.CustomErrorMessage = tailscale_access.DefaultErrorMessage
			}

			handler, err := tailscale_access.New(ctx, nextHandler, tc.config, "test-"+tc.name)
			if err != nil {
				t.Fatalf("tailscale_access.New() error = %v", err)
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

func TestTailscaleAuth_TrustedProxies(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name               string
		config             *tailscale_access.Config
		remoteAddr         string
		headers            map[string]string
		expectedStatusCode int
		expectAllow        bool
	}{
		{
			name: "Trust headers from trusted proxy",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				TrustedProxies:  []string{"172.17.0.0/16"},
				StrictMode:      true,
			},
			remoteAddr:         "172.17.0.1:12345", // Trusted proxy
			headers:            map[string]string{"X-Forwarded-For": "100.64.1.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
		{
			name: "Ignore headers from untrusted proxy",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				TrustedProxies:  []string{"172.17.0.0/16"},
				StrictMode:      true,
			},
			remoteAddr:         "8.8.8.8:12345", // Untrusted proxy
			headers:            map[string]string{"X-Forwarded-For": "100.64.1.1"},
			expectedStatusCode: http.StatusForbidden, // Should use RemoteAddr instead
			expectAllow:        false,
		},
		{
			name: "No trusted proxies configured - trust all",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
				TrustedProxies:  []string{}, // Empty means trust all
				StrictMode:      true,
			},
			remoteAddr:         "8.8.8.8:12345", // Any proxy
			headers:            map[string]string{"X-Forwarded-For": "100.64.1.1"},
			expectedStatusCode: http.StatusOK,
			expectAllow:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			handler, err := tailscale_access.New(ctx, nextHandler, tc.config, "test-"+tc.name)
			if err != nil {
				t.Fatalf("tailscale_access.New() error = %v", err)
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
		})
	}
}

func TestTailscaleAuth_StrictMode(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name               string
		strictMode         bool
		remoteAddr         string
		headers            map[string]string
		expectedStatusCode int
		description        string
	}{
		{
			name:               "Strict mode: only Tailscale IPs from headers",
			strictMode:         true,
			remoteAddr:         "172.17.0.1:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8, 100.64.1.1"},
			expectedStatusCode: http.StatusOK, // Should find and use 100.64.1.1
			description:        "Should find Tailscale IP in header list",
		},
		{
			name:               "Strict mode: no Tailscale IPs in headers, use RemoteAddr",
			strictMode:         true,
			remoteAddr:         "100.64.1.1:12345", // Tailscale IP
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8, 192.168.1.1"},
			expectedStatusCode: http.StatusOK, // Should fall back to RemoteAddr
			description:        "Should fall back to RemoteAddr when no Tailscale IPs in headers",
		},
		{
			name:               "Non-strict mode: use first IP from headers",
			strictMode:         false,
			remoteAddr:         "172.17.0.1:12345",
			headers:            map[string]string{"X-Forwarded-For": "8.8.8.8, 100.64.1.1"},
			expectedStatusCode: http.StatusForbidden, // 8.8.8.8 is not in allowed ranges
			description:        "Should use first IP (8.8.8.8) which is not allowed",
		},
		{
			name:               "Non-strict mode: first IP is allowed in additional ranges",
			strictMode:         false,
			remoteAddr:         "172.17.0.1:12345",
			headers:            map[string]string{"X-Forwarded-For": "127.0.0.1, 100.64.1.1"},
			expectedStatusCode: http.StatusOK, // 127.0.0.1 should be in additional ranges
			description:        "Should use first IP which is in additional ranges",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			config := &tailscale_access.Config{
				TailscaleRanges:  []string{"100.64.0.0/10"},
				AdditionalRanges: []string{"127.0.0.1/32"},
				HeadersToCheck:   []string{"X-Forwarded-For"},
				StrictMode:       tc.strictMode,
			}

			handler, err := tailscale_access.New(ctx, nextHandler, config, "test-"+tc.name)
			if err != nil {
				t.Fatalf("tailscale_access.New() error = %v", err)
			}

			recorder := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s: Expected status code %d, got %d", tc.description, tc.expectedStatusCode, recorder.Code)
			}
		})
	}
}

func TestTailscaleAuth_EdgeCases(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name               string
		config             *tailscale_access.Config
		remoteAddr         string
		headers            map[string]string
		expectedStatusCode int
	}{
		{
			name:               "No valid IP (empty RemoteAddr, no headers)",
			config:             tailscale_access.CreateConfig(),
			remoteAddr:         "",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "Invalid RemoteAddr format (no port)",
			config:             tailscale_access.CreateConfig(),
			remoteAddr:         "100.64.1.1", // No port, but should work
			headers:            nil,
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "Empty port in RemoteAddr",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
			},
			remoteAddr:         ":12345",
			headers:            nil,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name: "Invalid IP in header",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Forwarded-For"},
			},
			remoteAddr:         "100.64.1.1:12345",
			headers:            map[string]string{"X-Forwarded-For": "invalid-ip, also-invalid"},
			expectedStatusCode: http.StatusOK, // Should fall back to RemoteAddr
		},
		{
			name: "Multiple headers, use first populated",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				HeadersToCheck:  []string{"X-Real-IP", "X-Forwarded-For"},
				StrictMode:      true,
			},
			remoteAddr: "172.17.0.1:12345",
			headers: map[string]string{
				"X-Real-IP":       "", // Empty
				"X-Forwarded-For": "100.64.1.1",
			},
			expectedStatusCode: http.StatusOK, // Should use X-Forwarded-For
		},
		{
			name: "Debug logging enabled (coverage test)",
			config: &tailscale_access.Config{
				TailscaleRanges:    []string{"100.64.0.0/10"},
				EnableDebugLogging: true,
			},
			remoteAddr:         "100.64.1.1:12345",
			headers:            nil,
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			handler, err := tailscale_access.New(ctx, nextHandler, tc.config, "test-"+tc.name)
			if err != nil {
				t.Fatalf("tailscale_access.New() error = %v", err)
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
		})
	}
}

func TestNew_ErrorCases(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	ctx := context.Background()

	testCases := []struct {
		name        string
		config      *tailscale_access.Config
		expectedErr string
	}{
		{
			name: "Invalid Tailscale CIDR",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/invalid"},
			},
			expectedErr: "invalid CIDR string",
		},
		{
			name: "Invalid Additional CIDR",
			config: &tailscale_access.Config{
				TailscaleRanges:  []string{"100.64.0.0/10"},
				AdditionalRanges: []string{"192.168.1.0/foo"},
			},
			expectedErr: "invalid CIDR string",
		},
		{
			name: "Invalid Trusted Proxy CIDR",
			config: &tailscale_access.Config{
				TailscaleRanges: []string{"100.64.0.0/10"},
				TrustedProxies:  []string{"172.17.0.0/bar"},
			},
			expectedErr: "invalid CIDR string",
		},
		{
			name: "No ranges configured",
			config: &tailscale_access.Config{
				TailscaleRanges:  []string{""},  // Empty string should be skipped
				AdditionalRanges: []string{""}, // Empty string should be skipped
			},
			expectedErr: "at least one valid TailscaleRange or AdditionalRange must be provided",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tailscale_access.New(ctx, nextHandler, tc.config, "test-new-error")
			if err == nil {
				t.Fatalf("Expected an error, but got nil")
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("Expected error message to contain %q, got %q", tc.expectedErr, err.Error())
			}
		})
	}
}

func TestCreateConfig_Defaults(t *testing.T) {
	config := tailscale_access.CreateConfig()

	// Check default values
	if len(config.TailscaleRanges) != 1 || config.TailscaleRanges[0] != tailscale_access.DefaultTailscaleCIDR {
		t.Errorf("Expected default TailscaleRanges to be [%s], got %v", tailscale_access.DefaultTailscaleCIDR, config.TailscaleRanges)
	}

	if len(config.AdditionalRanges) != 0 {
		t.Errorf("Expected default AdditionalRanges to be empty, got %v", config.AdditionalRanges)
	}

	if config.EnableDebugLogging {
		t.Errorf("Expected default EnableDebugLogging to be false, got true")
	}

	if config.CustomErrorMessage != tailscale_access.DefaultErrorMessage {
		t.Errorf("Expected default CustomErrorMessage to be %q, got %q", tailscale_access.DefaultErrorMessage, config.CustomErrorMessage)
	}

	if !config.StrictMode {
		t.Errorf("Expected default StrictMode to be true, got false")
	}

	if len(config.TrustedProxies) != 0 {
		t.Errorf("Expected default TrustedProxies to be empty, got %v", config.TrustedProxies)
	}
}

// Benchmark tests
func BenchmarkTailscaleAuth_RemoteAddr(b *testing.B) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := tailscale_access.CreateConfig()
	handler, _ := tailscale_access.New(context.Background(), nextHandler, config, "benchmark")

	req, _ := http.NewRequest(http.MethodGet, "http://localhost", nil)
	req.RemoteAddr = "100.64.1.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	}
}

func BenchmarkTailscaleAuth_Headers(b *testing.B) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TailscaleRanges: []string{"100.64.0.0/10"},
		HeadersToCheck:  []string{"X-Forwarded-For", "X-Real-IP"},
		StrictMode:      true,
	}
	handler, _ := tailscale_access.New(context.Background(), nextHandler, config, "benchmark")

	req, _ := http.NewRequest(http.MethodGet, "http://localhost", nil)
	req.RemoteAddr = "172.17.0.1:12345"
	req.Header.Set("X-Forwarded-For", "100.64.1.1, 192.168.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	}
}