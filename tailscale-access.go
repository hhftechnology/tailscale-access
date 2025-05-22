// Package tailscaleauth provides Tailscale-aware IP authentication for Traefik
package tailscaleauth

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "strings"
    "os"
)

// Config represents the configuration options for our Tailscale authentication plugin
// Think of this as the control panel where you can adjust how the plugin behaves
type Config struct {
    // TailscaleRanges defines the IP ranges that should be allowed access
    // Default is the Tailscale CGNAT range, but you can customize this
    TailscaleRanges []string `json:"tailscaleRanges,omitempty"`
    
    // AdditionalRanges allows other IP ranges beyond Tailscale (like localhost for testing)
    AdditionalRanges []string `json:"additionalRanges,omitempty"`
    
    // HeadersToCheck tells the plugin which HTTP headers might contain the real client IP
    // This is crucial for your complex networking setup
    HeadersToCheck []string `json:"headersToCheck,omitempty"`
    
    // EnableDebugLogging helps you see what's happening during troubleshooting
    EnableDebugLogging bool `json:"enableDebugLogging,omitempty"`
    
    // CustomErrorMessage allows you to personalize the rejection message
    CustomErrorMessage string `json:"customErrorMessage,omitempty"`
}

// CreateConfig creates the default plugin configuration
// This is like setting up sensible defaults for a new installation
func CreateConfig() *Config {
    return &Config{
        // Default Tailscale CGNAT range - this covers all Tailscale IPs
        TailscaleRanges: []string{"100.64.0.0/10"},
        
        // Common headers where the real IP might be hiding in your setup
        HeadersToCheck: []string{
            "X-Forwarded-For",
            "X-Real-IP", 
            "X-Original-Forwarded-For",
            "CF-Connecting-IP",
            "True-Client-IP",
            "X-Client-IP",
        },
        
        // Start with debugging disabled for production
        EnableDebugLogging: false,
        
        // Default error message
        CustomErrorMessage: "Access denied: Tailscale connection required",
    }
}

// TailscaleAuth represents our middleware instance
// Think of this as your security guard who knows the rules and applies them
type TailscaleAuth struct {
    next   http.Handler
    config *Config
    name   string
}

// New creates a new instance of the Tailscale authentication middleware
// This is where we "hire" our security guard and give them their instructions
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    // Validate that we have at least one IP range to check
    if len(config.TailscaleRanges) == 0 && len(config.AdditionalRanges) == 0 {
        return nil, fmt.Errorf("tailscale-auth plugin requires at least one IP range to be configured")
    }
    
    return &TailscaleAuth{
        next:   next,
        config: config,
        name:   name,
    }, nil
}

// ServeHTTP is the main function that processes each incoming request
// This is where our security guard examines each visitor
func (t *TailscaleAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    // Step 1: Find the real client IP using our intelligent detection
    clientIP := t.extractRealClientIP(req)
    
    // Step 2: Log what we're doing if debugging is enabled
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("Checking IP: %s for request to %s", clientIP, req.URL.Path))
    }
    
    // Step 3: Check if this IP is allowed access
    if t.isIPAllowed(clientIP) {
        // IP is allowed - let them through to the next middleware or service
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("Allowing access for IP: %s", clientIP))
        }
        t.next.ServeHTTP(rw, req)
        return
    }
    
    // Step 4: IP is not allowed - block access with a clear message
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("Blocking access for IP: %s", clientIP))
    }
    
    // Send a 403 Forbidden response with our custom message
    rw.WriteHeader(http.StatusForbidden)
    rw.Write([]byte(t.config.CustomErrorMessage))
}

// extractRealClientIP implements our intelligent IP detection logic
// This is the detective work - looking in all the right places for the real Tailscale IP
func (t *TailscaleAuth) extractRealClientIP(req *http.Request) string {
    // Start by checking the direct connection IP
    directIP := t.getIPFromRemoteAddr(req.RemoteAddr)
    
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("Direct connection IP: %s", directIP))
    }
    
    // If the direct IP is already a Tailscale IP, we're done!
    if t.isIPInTailscaleRange(directIP) {
        return directIP
    }
    
    // The direct IP isn't Tailscale, so let's search through headers
    // This is where we handle your complex networking setup
    for _, header := range t.config.HeadersToCheck {
        headerValue := req.Header.Get(header)
        if headerValue != "" {
            if t.config.EnableDebugLogging {
                t.logDebug(fmt.Sprintf("Checking header %s: %s", header, headerValue))
            }
            
            // Headers might contain multiple IPs separated by commas
            // We need to check each one
            ips := strings.Split(headerValue, ",")
            for _, ip := range ips {
                cleanIP := strings.TrimSpace(ip)
                if t.isIPInTailscaleRange(cleanIP) {
                    if t.config.EnableDebugLogging {
                        t.logDebug(fmt.Sprintf("Found Tailscale IP in %s header: %s", header, cleanIP))
                    }
                    return cleanIP
                }
            }
        }
    }
    
    // If we couldn't find a Tailscale IP anywhere, return the direct IP
    // This allows the checking logic to properly reject non-Tailscale connections
    return directIP
}

// Helper function to extract IP from RemoteAddr (which includes port)
func (t *TailscaleAuth) getIPFromRemoteAddr(remoteAddr string) string {
    host, _, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        // If we can't parse it, return as-is
        return remoteAddr
    }
    return host
}

// Check if an IP is in the Tailscale CGNAT range
func (t *TailscaleAuth) isIPInTailscaleRange(ipStr string) bool {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        // Invalid IP format
        return false
    }
    
    // Check against all configured Tailscale ranges
    for _, rangeStr := range t.config.TailscaleRanges {
        _, cidr, err := net.ParseCIDR(rangeStr)
        if err != nil {
            // Skip invalid CIDR ranges
            continue
        }
        if cidr.Contains(ip) {
            return true
        }
    }
    
    return false
}

// Check if an IP is allowed (either Tailscale or additional ranges)
func (t *TailscaleAuth) isIPAllowed(ipStr string) bool {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        // Invalid IP format - reject
        return false
    }
    
    // First check if it's a Tailscale IP
    if t.isIPInTailscaleRange(ipStr) {
        return true
    }
    
    // Check additional allowed ranges (like localhost for testing)
    for _, rangeStr := range t.config.AdditionalRanges {
        _, cidr, err := net.ParseCIDR(rangeStr)
        if err != nil {
            // Skip invalid CIDR ranges
            continue
        }
        if cidr.Contains(ip) {
            return true
        }
    }
    
    // Not found in any allowed ranges
    return false
}

// logDebug outputs debug information when debugging is enabled
func (t *TailscaleAuth) logDebug(message string) {
    // Using os.Stdout is the recommended way to log from Traefik plugins
    os.Stdout.WriteString(fmt.Sprintf("[TailscaleAuth:%s] %s\n", t.name, message))
}