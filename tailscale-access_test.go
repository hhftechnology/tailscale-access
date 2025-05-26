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

func TestTailscaleConnectivityAuth_BasicFunctionality(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	testCases := []struct {
		name                     string
		config                   *tailscale_access.Config
		path                     string
		host                     string
		cookies                  []*http.Cookie
		expectedStatusCode       int
		expectedBodyContains     string
		expectVerificationPage   bool
		description              string
	}{
		{
			name: "Show verification page for unverified request",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				AllowLocalhost: false,
			},
			path:                   "/protected",
			host:                   "example.com",
			expectedStatusCode:     http.StatusOK,
			expectedBodyContains:   "Tailscale Verification",
			expectVerificationPage: true,
			description:           "Should show verification page when no valid cookie is present",
		},
		{
			name: "Allow localhost when configured",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				AllowLocalhost: true,
			},
			path:                   "/protected",
			host:                   "localhost",
			expectedStatusCode:     http.StatusOK,
			expectedBodyContains:   "Access granted",
			expectVerificationPage: false,
			description:           "Should bypass verification for localhost when configured",
		},
		{
			name: "Block localhost when not configured",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				AllowLocalhost: false,
			},
			path:                   "/protected",
			host:                   "localhost",
			expectedStatusCode:     http.StatusOK,
			expectedBodyContains:   "Tailscale Verification",
			expectVerificationPage: true,
			description:           "Should show verification page for localhost when bypass is disabled",
		},
		{
			name: "Allow access with valid verification cookie",
			config: &tailscale_access.Config{
				TestDomain: "test.ts.net",
			},
			path: "/protected",
			host: "example.com",
			cookies: []*http.Cookie{
				{
					Name:  "tailscale_verified",
					Value: "valid_token_12345abcdef",
				},
			},
			expectedStatusCode:     http.StatusOK,
			expectedBodyContains:   "Access granted",
			expectVerificationPage: false,
			description:           "Should allow access when valid verification cookie is present",
		},
		{
			name: "Reject invalid verification cookie",
			config: &tailscale_access.Config{
				TestDomain: "test.ts.net",
			},
			path: "/protected",
			host: "example.com",
			cookies: []*http.Cookie{
				{
					Name:  "tailscale_verified",
					Value: "short", // Too short to be valid
				},
			},
			expectedStatusCode:     http.StatusOK,
			expectedBodyContains:   "Tailscale Verification",
			expectVerificationPage: true,
			description:           "Should show verification page when cookie is too short",
		},
		{
			name: "Reject empty verification cookie",
			config: &tailscale_access.Config{
				TestDomain: "test.ts.net",
			},
			path: "/protected",
			host: "example.com",
			cookies: []*http.Cookie{
				{
					Name:  "tailscale_verified",
					Value: "",
				},
			},
			expectedStatusCode:     http.StatusOK,
			expectedBodyContains:   "Tailscale Verification",
			expectVerificationPage: true,
			description:           "Should show verification page when cookie is empty",
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
			
			// Add cookies if provided
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d. Description: %s", tc.expectedStatusCode, recorder.Code, tc.description)
			}

			if tc.expectedBodyContains != "" {
				bodyBytes, _ := io.ReadAll(recorder.Body)
				bodyString := string(bodyBytes)
				if !strings.Contains(bodyString, tc.expectedBodyContains) {
					t.Errorf("Expected body to contain %q, got %q. Description: %s", tc.expectedBodyContains, bodyString, tc.description)
				}
			}

			// Verify verification page contains test domain
			if tc.expectVerificationPage {
				bodyBytes, _ := io.ReadAll(recorder.Body)
				bodyString := string(bodyBytes)
				if !strings.Contains(bodyString, tc.config.TestDomain) {
					t.Errorf("Verification page should contain test domain %q. Description: %s", tc.config.TestDomain, tc.description)
				}
			}
		})
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
		description string
	}{
		{
			name:        "Missing test domain",
			config:      &tailscale_access.Config{},
			expectedErr: "testDomain must be configured",
			description: "Should reject configuration without test domain",
		},
		{
			name: "Invalid session timeout format",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				SessionTimeout: "invalid-duration",
			},
			expectedErr: "invalid sessionTimeout format",
			description: "Should reject invalid duration format",
		},
		{
			name: "Valid configuration with duration",
			config: &tailscale_access.Config{
				TestDomain:     "test.ts.net",
				SessionTimeout: "2h30m",
			},
			expectedErr: "",
			description: "Should accept valid duration format",
		},
		{
			name: "Valid minimal configuration",
			config: &tailscale_access.Config{
				TestDomain: "test.ts.net",
			},
			expectedErr: "",
			description: "Should accept minimal valid configuration",
		},
		{
			name: "Valid configuration with all options",
			config: &tailscale_access.Config{
				TestDomain:         "my-company.ts.net",
				SessionTimeout:     "24h",
				CustomErrorMessage: "Custom error",
				SuccessMessage:     "Custom success",
				EnableDebugLogging: true,
				AllowLocalhost:     false,
				CustomCSS:          "body { color: red; }",
				CustomScript:       "console.log('test');",
				SecureOnly:         false,
				CookieDomain:       ".example.com",
				RequireUserAgent:   false,
			},
			expectedErr: "",
			description: "Should accept comprehensive configuration",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := tailscale_access.New(ctx, nextHandler, tc.config, "test-config")
			
			if tc.expectedErr != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, but got nil. Description: %s", tc.expectedErr, tc.description)
				}
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("Expected error containing %q, got %q. Description: %s", tc.expectedErr, err.Error(), tc.description)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, but got %v. Description: %s", err, tc.description)
				}
			}
		})
	}
}

func TestCreateConfig_Defaults(t *testing.T) {
	config := tailscale_access.CreateConfig()

	// Check default values
	expectedDefaults := map[string]interface{}{
		"TestDomain":         "your-tailscale-network.ts.net",
		"SessionTimeout":     "24h",
		"AllowLocalhost":     true,
		"SecureOnly":         true,
		"RequireUserAgent":   true,
		"EnableDebugLogging": false,
	}

	if config.TestDomain != expectedDefaults["TestDomain"] {
		t.Errorf("Expected default TestDomain to be %q, got %q", expectedDefaults["TestDomain"], config.TestDomain)
	}

	if config.SessionTimeout != expectedDefaults["SessionTimeout"] {
		t.Errorf("Expected default SessionTimeout to be %q, got %q", expectedDefaults["SessionTimeout"], config.SessionTimeout)
	}

	if config.AllowLocalhost != expectedDefaults["AllowLocalhost"] {
		t.Errorf("Expected default AllowLocalhost to be %v, got %v", expectedDefaults["AllowLocalhost"], config.AllowLocalhost)
	}

	if config.SecureOnly != expectedDefaults["SecureOnly"] {
		t.Errorf("Expected default SecureOnly to be %v, got %v", expectedDefaults["SecureOnly"], config.SecureOnly)
	}

	if config.CustomErrorMessage == "" {
		t.Errorf("Expected default CustomErrorMessage to be set")
	}

	if config.SuccessMessage == "" {
		t.Errorf("Expected default SuccessMessage to be set")
	}
}

func TestTailscaleConnectivityAuth_CustomMessages(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain:         "custom.ts.net",
		CustomErrorMessage: "Custom error message for VPN access",
		SuccessMessage:     "Custom success message for verification",
		CustomCSS:          "body { background: red; }",
		CustomScript:       "console.log('Custom script loaded');",
	}

	ctx := context.Background()
	handler, err := tailscale_access.New(ctx, nextHandler, config, "test-custom")
	if err != nil {
		t.Fatalf("tailscale_access.New() error = %v", err)
	}

	// Test verification page contains custom configuration
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/protected", nil)

	handler.ServeHTTP(recorder, req)

	bodyBytes, _ := io.ReadAll(recorder.Body)
	bodyString := string(bodyBytes)

	expectedContent := []string{
		"custom.ts.net",                           // Custom domain
		"Custom success message for verification", // Custom success message
		"body { background: red; }",               // Custom CSS
		"console.log('Custom script loaded');",    // Custom script
	}

	for _, content := range expectedContent {
		if !strings.Contains(bodyString, content) {
			t.Errorf("Expected verification page to contain %q", content)
		}
	}
}

func TestTailscaleConnectivityAuth_LocalhostDetection(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Access granted"))
	})

	config := &tailscale_access.Config{
		TestDomain:     "test.ts.net",
		AllowLocalhost: true,
	}

	ctx := context.Background()
	handler, err := tailscale_access.New(ctx, nextHandler, config, "test-localhost")
	if err != nil {
		t.Fatalf("tailscale_access.New() error = %v", err)
	}

	localhostVariants := []string{
		"localhost",
		"localhost:8080",
		"127.0.0.1",
		"127.0.0.1:3000",
		"::1",
		"[::1]:8080",
	}

	for _, host := range localhostVariants {
		t.Run("localhost_"+host, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/test", nil)

			handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusOK {
				t.Errorf("Expected status 200 for localhost variant %q, got %d", host, recorder.Code)
			}

			bodyBytes, _ := io.ReadAll(recorder.Body)
			if !strings.Contains(string(bodyBytes), "Access granted") {
				t.Errorf("Expected access granted for localhost variant %q", host)
			}
		})
	}
}

func TestTailscaleConnectivityAuth_VerificationPageStructure(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain:         "verification-test.ts.net",
		CustomErrorMessage: "Test error message",
		SuccessMessage:     "Test success message",
	}

	ctx := context.Background()
	handler, err := tailscale_access.New(ctx, nextHandler, config, "test-verification")
	if err != nil {
		t.Fatalf("tailscale_access.New() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/protected?param=value", nil)

	handler.ServeHTTP(recorder, req)

	bodyBytes, _ := io.ReadAll(recorder.Body)
	bodyString := string(bodyBytes)

	// Check that the verification page has proper structure
	expectedElements := []string{
		"<!DOCTYPE html>",                    // Valid HTML
		"Tailscale Verification",             // Title
		"verification-test.ts.net",           // Test domain
		"verifyTailscaleConnectivity",        // Main function
		"setVerificationCookieAndRedirect",   // Cookie setting function
		"generateClientToken",                // Token generation
		"testImageLoad",                      // Fallback test
		"/protected?param=value",             // Original URL preservation
		"Test success message",               // Custom success message
		"tailscale.com/download",             // Help link
	}

	for _, element := range expectedElements {
		if !strings.Contains(bodyString, element) {
			t.Errorf("Expected verification page to contain %q", element)
		}
	}

	// Verify it's valid HTML structure
	if !strings.HasPrefix(bodyString, "<!DOCTYPE html>") {
		t.Errorf("Verification page should start with DOCTYPE declaration")
	}

	if !strings.Contains(bodyString, "</html>") {
		t.Errorf("Verification page should end with closing html tag")
	}
}

// Benchmark tests
func BenchmarkTailscaleConnectivityAuth_VerifiedRequest(b *testing.B) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain:     "benchmark.ts.net",
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

func BenchmarkTailscaleConnectivityAuth_CookieValidation(b *testing.B) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := &tailscale_access.Config{
		TestDomain: "benchmark.ts.net",
	}
	
	handler, _ := tailscale_access.New(context.Background(), nextHandler, config, "benchmark")
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "tailscale_verified",
		Value: "valid_benchmark_token_12345abcdef",
	})

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
		TestDomain: "benchmark.ts.net",
	}
	
	handler, _ := tailscale_access.New(context.Background(), nextHandler, config, "benchmark")
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	}
}

// Integration test simulating the full flow
func TestTailscaleConnectivityAuth_IntegrationFlow(t *testing.T) {
	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("Protected resource accessed"))
	})

	config := &tailscale_access.Config{
		TestDomain:         "integration.ts.net",
		SessionTimeout:     "1h",
		EnableDebugLogging: true,
		AllowLocalhost:     false,
		CustomErrorMessage: "Integration test error",
		SuccessMessage:     "Integration test success",
	}

	ctx := context.Background()
	handler, err := tailscale_access.New(ctx, nextHandler, config, "integration-test")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Step 1: First request without cookie should show verification page
	recorder1 := httptest.NewRecorder()
	req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/secure", nil)
	
	handler.ServeHTTP(recorder1, req1)
	
	if recorder1.Code != http.StatusOK {
		t.Errorf("Expected status 200 for verification page, got %d", recorder1.Code)
	}
	
	bodyBytes1, _ := io.ReadAll(recorder1.Body)
	body1 := string(bodyBytes1)
	
	if !strings.Contains(body1, "Tailscale Verification") {
		t.Errorf("Expected verification page")
	}
	
	if !strings.Contains(body1, "integration.ts.net") {
		t.Errorf("Expected test domain in verification page")
	}

	// Step 2: Request with valid cookie should allow access
	recorder2 := httptest.NewRecorder()
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/secure", nil)
	req2.AddCookie(&http.Cookie{
		Name:  "tailscale_verified",
		Value: "integration_test_token_abcdef123456",
	})
	
	handler.ServeHTTP(recorder2, req2)
	
	if recorder2.Code != http.StatusOK {
		t.Errorf("Expected status 200 for authenticated request, got %d", recorder2.Code)
	}
	
	bodyBytes2, _ := io.ReadAll(recorder2.Body)
	body2 := string(bodyBytes2)
	
	if !strings.Contains(body2, "Protected resource accessed") {
		t.Errorf("Expected access to protected resource, got: %s", body2)
	}

	// Step 3: Request with invalid/short cookie should show verification page
	recorder3 := httptest.NewRecorder()
	req3, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/secure", nil)
	req3.AddCookie(&http.Cookie{
		Name:  "tailscale_verified",
		Value: "short", // Too short to be valid
	})
	
	handler.ServeHTTP(recorder3, req3)
	
	bodyBytes3, _ := io.ReadAll(recorder3.Body)
	body3 := string(bodyBytes3)
	
	if !strings.Contains(body3, "Tailscale Verification") {
		t.Errorf("Expected verification page for invalid cookie")
	}
}