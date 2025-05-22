// Package main contains tests for the Tailscale authentication plugin
//
// These tests verify that our plugin correctly identifies and allows/blocks different
// types of IP addresses under various networking scenarios. Testing plugins is crucial
// because they operate in the security layer of your application.
//
// Note that we use 'package main' here instead of 'package main_test' because our
// plugin code is in the main package, and we need access to the unexported functions
// and types for thorough testing.
package main

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
)

// TestTailscaleAuth_BasicFunctionality tests the core plugin functionality
// This test verifies that the plugin correctly allows Tailscale IPs and blocks others
func TestTailscaleAuth_BasicFunctionality(t *testing.T) {
    // Create a test configuration with debugging enabled so we can see what's happening
    cfg := CreateConfig()
    cfg.EnableDebugLogging = true
    cfg.TailscaleRanges = []string{"100.64.0.0/10"}
    cfg.AdditionalRanges = []string{"127.0.0.1/32"} // Allow localhost for testing

    // Create a context and a simple "next" handler that represents the protected service
    ctx := context.Background()
    next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        rw.WriteHeader(http.StatusOK)
        rw.Write([]byte("Access granted - you reached the protected service"))
    })

    // Create our plugin instance using the same factory function Traefik would use
    handler, err := New(ctx, next, cfg, "tailscale-auth-test")
    if err != nil {
        t.Fatalf("Failed to create plugin instance: %v", err)
    }

    // Test Case 1: Tailscale IP should be allowed
    t.Run("Allow Tailscale IP", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/protected", nil)
        
        // Simulate a request coming from a Tailscale IP
        // The format includes a port number as Traefik would provide it
        req.RemoteAddr = "100.64.1.100:12345"
        
        handler.ServeHTTP(recorder, req)
        
        // Verify that the request was allowed through
        if recorder.Code != http.StatusOK {
            t.Errorf("Expected status 200 for Tailscale IP, got %d. Body: %s", recorder.Code, recorder.Body.String())
        }
        
        // Verify that the protected service was actually reached
        expectedBody := "Access granted - you reached the protected service"
        if recorder.Body.String() != expectedBody {
            t.Errorf("Expected body '%s', got '%s'", expectedBody, recorder.Body.String())
        }
    })

    // Test Case 2: Non-Tailscale IP should be blocked
    t.Run("Block non-Tailscale IP", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/protected", nil)
        
        // Simulate a request from a regular internet IP that's not in Tailscale ranges
        req.RemoteAddr = "192.168.1.100:12345"
        
        handler.ServeHTTP(recorder, req)
        
        // Verify that the request was blocked
        if recorder.Code != http.StatusForbidden {
            t.Errorf("Expected status 403 for non-Tailscale IP, got %d", recorder.Code)
        }
        
        // Verify that our custom error message was returned
        expectedMessage := cfg.CustomErrorMessage
        if recorder.Body.String() != expectedMessage {
            t.Errorf("Expected error message '%s', got '%s'", expectedMessage, recorder.Body.String())
        }
    })

    // Test Case 3: Localhost should be allowed (from additionalRanges)
    t.Run("Allow localhost from additional ranges", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/protected", nil)
        
        // Simulate a request from localhost
        req.RemoteAddr = "127.0.0.1:8080"
        
        handler.ServeHTTP(recorder, req)
        
        // Localhost should be allowed because it's in our additionalRanges
        if recorder.Code != http.StatusOK {
            t.Errorf("Expected status 200 for localhost, got %d. Body: %s", recorder.Code, recorder.Body.String())
        }
    })
}

// TestTailscaleAuth_HeaderDetection tests the intelligent IP detection through headers
// This is crucial for complex networking setups where the real IP is in forwarding headers
func TestTailscaleAuth_HeaderDetection(t *testing.T) {
    cfg := CreateConfig()
    cfg.EnableDebugLogging = true
    cfg.TailscaleRanges = []string{"100.64.0.0/10"}
    
    ctx := context.Background()
    next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        rw.WriteHeader(http.StatusOK)
        rw.Write([]byte("Success"))
    })

    handler, err := New(ctx, next, cfg, "header-test")
    if err != nil {
        t.Fatalf("Failed to create plugin instance: %v", err)
    }

    // Test Case 1: Tailscale IP in X-Forwarded-For header
    t.Run("Detect Tailscale IP in X-Forwarded-For", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
        
        // Simulate a proxy setup where the direct connection is from a proxy server
        // but the real client IP is preserved in the X-Forwarded-For header
        req.RemoteAddr = "172.17.0.1:12345" // Docker container IP (proxy)
        req.Header.Set("X-Forwarded-For", "100.64.1.200") // Real Tailscale client
        
        handler.ServeHTTP(recorder, req)
        
        // Should be allowed because we found the Tailscale IP in the header
        if recorder.Code != http.StatusOK {
            t.Errorf("Expected status 200 when Tailscale IP in header, got %d", recorder.Code)
        }
    })

    // Test Case 2: Multiple IPs in X-Forwarded-For (common in proxy chains)
    t.Run("Detect Tailscale IP in multi-hop X-Forwarded-For", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
        
        // Simulate a chain of proxies where multiple IPs are recorded
        // Format: "original-client, proxy1, proxy2"
        req.RemoteAddr = "10.0.0.5:12345" // Final proxy
        req.Header.Set("X-Forwarded-For", "100.64.2.50, 172.17.0.1, 10.0.0.4")
        
        handler.ServeHTTP(recorder, req)
        
        // Should find and allow the Tailscale IP (100.64.2.50) from the chain
        if recorder.Code != http.StatusOK {
            t.Errorf("Expected status 200 when Tailscale IP in forwarded chain, got %d", recorder.Code)
        }
    })

    // Test Case 3: No Tailscale IP anywhere should be blocked
    t.Run("Block when no Tailscale IP found", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
        
        // Simulate a request where neither the direct IP nor any headers contain a Tailscale IP
        req.RemoteAddr = "203.0.113.1:12345" // External internet IP
        req.Header.Set("X-Forwarded-For", "198.51.100.1, 172.16.0.1") // More external IPs
        req.Header.Set("X-Real-IP", "203.0.113.2") // Another external IP
        
        handler.ServeHTTP(recorder, req)
        
        // Should be blocked since no Tailscale IPs were found anywhere
        if recorder.Code != http.StatusForbidden {
            t.Errorf("Expected status 403 when no Tailscale IP found, got %d", recorder.Code)
        }
    })
}

// TestTailscaleAuth_ConfigValidation tests that the plugin properly validates its configuration
func TestTailscaleAuth_ConfigValidation(t *testing.T) {
    ctx := context.Background()
    next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        rw.WriteHeader(http.StatusOK)
    })

    // Test Case 1: Empty configuration should be rejected
    t.Run("Reject empty configuration", func(t *testing.T) {
        emptyConfig := &Config{
            // No ranges configured at all
            TailscaleRanges:  []string{},
            AdditionalRanges: []string{},
        }
        
        _, err := New(ctx, next, emptyConfig, "empty-config-test")
        
        // Should return an error because we have no IP ranges to check against
        if err == nil {
            t.Error("Expected error for empty configuration, but got none")
        }
        
        // Verify the error message makes sense
        expectedError := "requires at least one IP range"
        if !containsString(err.Error(), expectedError) {
            t.Errorf("Expected error to contain '%s', got: %s", expectedError, err.Error())
        }
    })

    // Test Case 2: Valid configuration should be accepted
    t.Run("Accept valid configuration", func(t *testing.T) {
        validConfig := CreateConfig() // Use our default config which should be valid
        
        _, err := New(ctx, next, validConfig, "valid-config-test")
        
        // Should not return an error
        if err != nil {
            t.Errorf("Expected no error for valid configuration, got: %v", err)
        }
    })
}

// TestTailscaleAuth_IPRangeMatching tests various IP range scenarios
func TestTailscaleAuth_IPRangeMatching(t *testing.T) {
    // Create a plugin instance for testing IP range logic
    cfg := &Config{
        TailscaleRanges:  []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}, // IPv4 and IPv6
        AdditionalRanges: []string{"192.168.1.0/24"},
        EnableDebugLogging: true,
    }
    
    ctx := context.Background()
    next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        rw.WriteHeader(http.StatusOK)
    })
    
    handler, err := New(ctx, next, cfg, "range-test")
    if err != nil {
        t.Fatalf("Failed to create test instance: %v", err)
    }
    
    // Cast to our concrete type so we can test internal methods
    plugin := handler.(*TailscaleAuth)

    // Test cases for IP range matching
    testCases := []struct {
        name     string
        ip       string
        expected bool
        reason   string
    }{
        {
            name:     "Tailscale CGNAT start",
            ip:       "100.64.0.1",
            expected: true,
            reason:   "Should match start of Tailscale range",
        },
        {
            name:     "Tailscale CGNAT middle",
            ip:       "100.80.50.100",
            expected: true,
            reason:   "Should match middle of Tailscale range",
        },
        {
            name:     "Tailscale CGNAT end",
            ip:       "100.127.255.254",
            expected: true,
            reason:   "Should match near end of Tailscale range",
        },
        {
            name:     "Just outside Tailscale range",
            ip:       "100.128.0.1",
            expected: false,
            reason:   "Should not match IPs outside Tailscale range",
        },
        {
            name:     "Additional range match",
            ip:       "192.168.1.50",
            expected: true,
            reason:   "Should match additional allowed ranges",
        },
        {
            name:     "Completely unrelated IP",
            ip:       "8.8.8.8",
            expected: false,
            reason:   "Should not match public internet IPs",
        },
        {
            name:     "Invalid IP format",
            ip:       "not.an.ip.address",
            expected: false,
            reason:   "Should reject invalid IP formats",
        },
        {
            name:     "Empty IP",
            ip:       "",
            expected: false,
            reason:   "Should reject empty IP strings",
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            result := plugin.isIPAllowed(tc.ip)
            if result != tc.expected {
                t.Errorf("IP %s: expected %v, got %v. Reason: %s", tc.ip, tc.expected, result, tc.reason)
            }
        })
    }
}

// TestTailscaleAuth_CustomErrorMessage tests that custom error messages work correctly
func TestTailscaleAuth_CustomErrorMessage(t *testing.T) {
    customMessage := "Sorry! You need to connect through our secure Tailscale network to access this resource. Contact IT for help."
    
    cfg := CreateConfig()
    cfg.CustomErrorMessage = customMessage
    cfg.TailscaleRanges = []string{"100.64.0.0/10"}
    
    ctx := context.Background()
    next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        rw.WriteHeader(http.StatusOK)
    })

    handler, err := New(ctx, next, cfg, "custom-message-test")
    if err != nil {
        t.Fatalf("Failed to create plugin instance: %v", err)
    }

    // Test that blocked requests return our custom message
    recorder := httptest.NewRecorder()
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
    req.RemoteAddr = "203.0.113.1:12345" // External IP that should be blocked
    
    handler.ServeHTTP(recorder, req)
    
    // Verify the custom message is returned
    if recorder.Code != http.StatusForbidden {
        t.Errorf("Expected status 403, got %d", recorder.Code)
    }
    
    if recorder.Body.String() != customMessage {
        t.Errorf("Expected custom message '%s', got '%s'", customMessage, recorder.Body.String())
    }
}

// containsString is a helper function to check if a string contains a substring
// This is useful for checking error messages without requiring exact matches
func containsString(haystack, needle string) bool {
    return len(haystack) >= len(needle) && 
           (len(needle) == 0 || 
            haystack == needle || 
            (len(haystack) > len(needle) && 
             (haystack[:len(needle)] == needle || 
              haystack[len(haystack)-len(needle):] == needle || 
              containsSubstring(haystack, needle))))
}

// containsSubstring checks if needle exists as a substring in haystack
func containsSubstring(haystack, needle string) bool {
    if len(needle) == 0 {
        return true
    }
    if len(needle) > len(haystack) {
        return false
    }
    
    for i := 0; i <= len(haystack)-len(needle); i++ {
        if haystack[i:i+len(needle)] == needle {
            return true
        }
    }
    return false
}