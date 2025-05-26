package tailscale_access_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	tailscale_access "github.com/hhftechnology/tailscale-access"
)

func TestTailscaleConnectivityAuth_BasicFunctionality(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name               string
		config             *tailscale_access.Config
		path               string
		host               string
		headers            map[string]string
		expectedStatusCode int
		expectedBodyContains string
		expectVerificationPage bool
	}{
		{
			name: "Show verification page for unverified request",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				AllowLocalhost: false,
			},
			path:               "/protected",
			host:               "example.com",
			expectedStatusCode: http.StatusOK,
			expectedBodyContains: "Tailscale Verification",
			expectVerificationPage: true,
		},
		{
			name: "Allow localhost when configured",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				AllowLocalhost: true,
			},
			path:               "/protected",
			host:               "localhost",
			expectedStatusCode: http.StatusOK,
			expectedBodyContains: "Access granted",
			expectVerificationPage: false,
		},
		{
			name: "Block localhost when not configured",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				AllowLocalhost: false,
			},
			path:               "/protected",
			host:               "localhost",
			expectedStatusCode: http.StatusOK,
			expectedBodyContains: "Tailscale Verification",
			expectVerificationPage: true,
		},
		{
			name: "Allow access with valid verification cookie",
			config: &tailscale_access.Config{
				TestDomain: "test.ts.net",
			},
			path:               "/protected",
			host:               "example.com",
			headers:            map[string]string{"Cookie": "tailscale_verified=valid_token"},
			expectedStatusCode: http.StatusOK,
			expectedBodyContains: "Access granted", // This will fail initially as the token isn't in the store
			expectVerificationPage: false,
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
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+tc.host+tc.path, nil)
			
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedStatusCode, recorder.Code)
			}

			if tc.expectedBodyContains != "" {
				bodyBytes, _ := io.ReadAll(recorder.Body)
				bodyString := string(bodyBytes)
				if !strings.Contains(bodyString, tc.expectedBodyContains) {
					t.Errorf("Expected body to contain %q, got %q", tc.expectedBodyContains, bodyString)
				}
			}
		})
	}
}

func TestTailscaleConnectivityAuth_VerificationEndpoint(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name               string
		method             string
		formData           map[string]string
		expectedStatusCode int
		expectedBodyContains string
	}{
		{
			name:               "Successful verification",
			method:             http.MethodPost,
			formData:           map[string]string{"status": "success", "originalURL": "/test"},
			expectedStatusCode: http.StatusOK,
			expectedBodyContains: `"success": true`,
		},
		{
			name:               "Failed verification",
			method:             http.MethodPost,
			formData:           map[string]string{"status": "failure", "originalURL": "/test"},
			expectedStatusCode: http.StatusForbidden,
			expectedBodyContains: `"success": false`,
		},
		{
			name:               "Invalid method",
			method:             http.MethodGet,
			expectedStatusCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			config := &tailscale_access.Config{
				TestDomain: "test.ts.net",
			}

			handler, err := tailscale_access.New(ctx, nextHandler, config, "test-verification")
			if err != nil {
				t.Fatalf("tailscale_access.New() error = %v", err)
			}

			// Prepare request body
			var body io.Reader
			if tc.formData != nil {
				formValues := url.Values{}
				for k, v := range tc.formData {
					formValues.Set(k, v)
				}
				body = strings.NewReader(formValues.Encode())
			}

			recorder := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(ctx, tc.method, "http://example.com/__tailscale_verify", body)
			
			if tc.formData != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedStatusCode, recorder.Code)
			}

			if tc.expectedBodyContains != "" {
				bodyBytes, _ := io.ReadAll(recorder.Body)
				bodyString := string(bodyBytes)
				if !strings.Contains(bodyString, tc.expectedBodyContains) {
					t.Errorf("Expected body to contain %q, got %q", tc.expectedBodyContains, bodyString)
				}
			}
		})
	}
}

func TestTailscaleConnectivityAuth_SessionManagement(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	ctx := context.Background()
	config := &tailscale_access.Config{
		TestDomain:     "test.ts.net",
		SessionTimeout: 1 * time.Second, // Short timeout for testing
	}

	handler, err := tailscale_access.New(ctx, nextHandler, config, "test-session")
	if err != nil {
		t.Fatalf("tailscale_access.New() error = %v", err)
	}

	// First, perform a successful verification to get a token
	recorder1 := httptest.NewRecorder()
	formData := url.Values{}
	formData.Set("status", "success")
	formData.Set("originalURL", "/test")
	
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com/__tailscale_verify", 
		strings.NewReader(formData.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.ServeHTTP(recorder1, req1)

	if recorder1.Code != http.StatusOK {
		t.Fatalf("Expected successful verification, got status %d", recorder1.Code)
	}

	// Extract the cookie from the response
	cookies := recorder1.Result().Cookies()
	var verificationCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "tailscale_verified" {
			verificationCookie = cookie
			break
		}
	}

	if verificationCookie == nil {
		t.Fatalf("Expected verification cookie to be set")
	}

	// Test that the cookie allows access immediately
	recorder2 := httptest.NewRecorder()
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/protected", nil)
	req2.AddCookie(verificationCookie)

	handler.ServeHTTP(recorder2, req2)

	if recorder2.Code != http.StatusOK {
		t.Errorf("Expected access with valid cookie, got status %d", recorder2.Code)
	}

	bodyBytes, _ := io.ReadAll(recorder2.Body)
	if !strings.Contains(string(bodyBytes), "Access granted") {
		t.Errorf("Expected access granted, got %s", string(bodyBytes))
	}

	// Wait for the session to expire
	time.Sleep(2 * time.Second)

	// Test that the expired cookie no longer allows access
	recorder3 := httptest.NewRecorder()
	req3, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/protected", nil)
	req3.AddCookie(verificationCookie)

	handler.ServeHTTP(recorder3, req3)

	bodyBytes3, _ := io.ReadAll(recorder3.Body)
	if !strings.Contains(string(bodyBytes3), "Tailscale Verification") {
		t.Errorf("Expected verification page after session expiry, got %s", string(bodyBytes3))
	}
}

func TestTailscaleConnectivityAuth_Configuration(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	testCases := []struct {
		name        string
		config      *tailscale_access.Config
		expectedErr string
	}{
		{
			name:        "Missing test domain",
			config:      &tailscale_access.Config{},
			expectedErr: "testDomain must be configured",
		},
		{
			name: "Valid configuration",
			config: &tailscale_access.Config{
				TestDomain: "test.ts.net",
			},
			expectedErr: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := tailscale_access.New(ctx, nextHandler, tc.config, "test-config")
			
			if tc.expectedErr != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, but got nil", tc.expectedErr)
				}
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("Expected error containing %q, got %q", tc.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, but got %v", err)
				}
			}
		})
	}
}

func TestCreateConfig_Defaults(t *testing.T) {
	config := tailscale_access.CreateConfig()

	// Check default values
	if config.TestDomain != "your-tailscale-network.ts.net" {
		t.Errorf("Expected default TestDomain to be 'your-tailscale-network.ts.net', got %s", config.TestDomain)
	}

	if config.SessionTimeout != 24*time.Hour {
		t.Errorf("Expected default SessionTimeout to be 24h, got %v", config.SessionTimeout)
	}

	if !config.AllowLocalhost {
		t.Errorf("Expected default AllowLocalhost to be true, got false")
	}

	if !config.SecureOnly {
		t.Errorf("Expected default SecureOnly to be true, got false")
	}

	if config.CustomErrorMessage == "" {
		t.Errorf("Expected default CustomErrorMessage to be set")
	}
}

func TestTailscaleConnectivityAuth_CustomMessages(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain:         "custom.ts.net",
		CustomErrorMessage: "Custom error message",
		SuccessMessage:     "Custom success message",
	}

	ctx := context.Background()
	handler, err := tailscale_access.New(ctx, nextHandler, config, "test-custom")
	if err != nil {
		t.Fatalf("tailscale_access.New() error = %v", err)
	}

	// Test verification page contains custom domain
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/protected", nil)

	handler.ServeHTTP(recorder, req)

	bodyBytes, _ := io.ReadAll(recorder.Body)
	bodyString := string(bodyBytes)

	if !strings.Contains(bodyString, "custom.ts.net") {
		t.Errorf("Expected verification page to contain custom domain")
	}

	// Test successful verification response contains custom success message
	recorder2 := httptest.NewRecorder()
	formData := url.Values{}
	formData.Set("status", "success")
	formData.Set("originalURL", "/test")
	
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com/__tailscale_verify", 
		strings.NewReader(formData.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.ServeHTTP(recorder2, req2)

	bodyBytes2, _ := io.ReadAll(recorder2.Body)
	if !strings.Contains(string(bodyBytes2), "Custom success message") {
		t.Errorf("Expected success response to contain custom success message")
	}
}

// Benchmark tests
func BenchmarkTailscaleConnectivityAuth_VerifiedRequest(b *testing.B) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain:     "test.ts.net",
		AllowLocalhost: true,
	}
	
	handler, _ := tailscale_access.New(context.Background(), nextHandler, config, "benchmark")

	req, _ := http.NewRequest(http.MethodGet, "http://localhost/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	}
}

func BenchmarkTailscaleConnectivityAuth_VerificationPage(b *testing.B) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain: "test.ts.net",
	}
	
	handler, _ := tailscale_access.New(context.Background(), nextHandler, config, "benchmark")

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	}
}