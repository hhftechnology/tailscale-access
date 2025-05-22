package tailscaleauth_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/hhftechnology/tailscale-access"
)

func TestTailscaleAuth(t *testing.T) {
    // Create configuration for testing
    cfg := tailscaleauth.CreateConfig()
    cfg.EnableDebugLogging = true
    cfg.TailscaleRanges = []string{"100.64.0.0/10"}
    cfg.AdditionalRanges = []string{"127.0.0.1/32"} // Allow localhost for testing

    ctx := context.Background()
    next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        rw.WriteHeader(http.StatusOK)
        rw.Write([]byte("Access granted"))
    })

    handler, err := tailscaleauth.New(ctx, next, cfg, "tailscale-auth-test")
    if err != nil {
        t.Fatal(err)
    }

    // Test 1: Allow Tailscale IP
    t.Run("Allow Tailscale IP", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
        req.RemoteAddr = "100.64.1.100:12345" // Fake Tailscale IP
        
        handler.ServeHTTP(recorder, req)
        
        if recorder.Code != http.StatusOK {
            t.Errorf("Expected status 200, got %d", recorder.Code)
        }
    })

    // Test 2: Block non-Tailscale IP
    t.Run("Block non-Tailscale IP", func(t *testing.T) {
        recorder := httptest.NewRecorder()
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
        req.RemoteAddr = "192.168.1.100:12345" // Non-Tailscale IP
        
        handler.ServeHTTP(recorder, req)
        
        if recorder.Code != http.StatusForbidden {
            t.Errorf("Expected status 403, got %d", recorder.Code)
        }
    })
}