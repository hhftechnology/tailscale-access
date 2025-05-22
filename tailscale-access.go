// Package main implements the Tailscale authentication plugin for Traefik
// 
// This plugin solves the complex challenge of identifying real client IPs in networking 
// setups where standard IP allowlists fail, particularly when using Tailscale with 
// reverse proxies, Docker networking, and multiple networking layers.
//
// The key insight here is that Traefik plugins must use 'package main' rather than
// a named package. This is because Traefik loads plugins using the Yaegi interpreter,
// which expects standalone Go programs rather than importable libraries.
package main

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "strings"
    "os"
)

// Config represents the configuration options for our Tailscale authentication plugin
// This struct defines all the knobs and switches that users can adjust to customize
// how the plugin behaves in their specific networking environment.
//
// The JSON tags are crucial here - they tell Traefik how to map YAML configuration
// values to our Go struct fields. The 'omitempty' tag means these fields are optional.
type Config struct {
    // TailscaleRanges defines the IP ranges that should be considered valid Tailscale connections
    // Default is "100.64.0.0/10" which covers Tailscale's standard CGNAT range
    // You might need to customize this if your Tailscale network uses different ranges
    TailscaleRanges []string `json:"tailscaleRanges,omitempty"`
    
    // AdditionalRanges allows access from non-Tailscale sources like localhost for development
    // This is helpful during testing or when you have legitimate non-Tailscale sources
    AdditionalRanges []string `json:"additionalRanges,omitempty"`
    
    // HeadersToCheck tells the plugin which HTTP headers might contain the real client IP
    // This is the secret sauce for handling complex proxy setups where the original
    // Tailscale IP gets buried in forwarding headers
    HeadersToCheck []string `json:"headersToCheck,omitempty"`
    
    // EnableDebugLogging provides detailed information about IP detection and decisions
    // Essential for troubleshooting but should be disabled in production for performance
    EnableDebugLogging bool `json:"enableDebugLogging,omitempty"`
    
    // CustomErrorMessage allows you to personalize the access denied message
    // A clear message helps users understand how to gain proper access
    CustomErrorMessage string `json:"customErrorMessage,omitempty"`
}

// CreateConfig creates the default plugin configuration
// This function is required by Traefik's plugin system - it's called when the plugin
// is first loaded to establish sensible defaults. Think of it as the "factory settings"
// for your plugin that users can then customize.
func CreateConfig() *Config {
    return &Config{
        // Default to Tailscale's standard CGNAT range - this covers the vast majority of cases
        TailscaleRanges: []string{"100.64.0.0/10"},
        
        // Common headers where proxy servers store the original client IP
        // The order matters - we check these sequentially until we find a Tailscale IP
        HeadersToCheck: []string{
            "X-Forwarded-For",        // Most common forwarding header
            "X-Real-IP",             // Nginx and other proxies
            "X-Original-Forwarded-For", // Some complex proxy setups
            "CF-Connecting-IP",       // Cloudflare
            "True-Client-IP",        // Some CDNs and load balancers
            "X-Client-IP",           // Generic client IP header
        },
        
        // Start with debugging disabled for production safety
        EnableDebugLogging: false,
        
        // Clear, helpful default error message
        CustomErrorMessage: "Access denied: Tailscale connection required",
    }
}

// TailscaleAuth represents our middleware instance
// This struct holds the state for a single instance of our middleware. Traefik might
// create multiple instances if you use the middleware on different routes with different
// configurations, so each instance needs its own state.
type TailscaleAuth struct {
    next   http.Handler  // The next middleware or handler in the chain
    config *Config       // Our configuration for this instance
    name   string        // The name of this middleware instance (for logging)
}

// New creates a new instance of the Tailscale authentication middleware
// This is the factory function that Traefik calls to create instances of your middleware.
// The function signature is strictly defined by Traefik's plugin system - you must
// match this exactly or the plugin won't load.
//
// Parameters:
//   ctx: Context for the operation (though we don't use it much in this plugin)
//   next: The next handler in the middleware chain
//   config: The configuration for this specific middleware instance
//   name: A unique name for this middleware instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    // Validate that we have at least one IP range to check against
    // Without any ranges, the plugin would either block everything or allow everything,
    // neither of which is useful for security
    if len(config.TailscaleRanges) == 0 && len(config.AdditionalRanges) == 0 {
        return nil, fmt.Errorf("tailscale-auth plugin requires at least one IP range to be configured")
    }
    
    // Create and return our middleware instance
    // This instance will handle all requests that flow through this middleware
    return &TailscaleAuth{
        next:   next,
        config: config,
        name:   name,
    }, nil
}

// ServeHTTP is the main function that processes each incoming HTTP request
// This is where the actual security logic happens. Every request that hits a route
// protected by this middleware will flow through this function.
//
// The logic follows a simple but effective pattern:
// 1. Find the real client IP (the detective work)
// 2. Check if that IP is allowed (the security decision)
// 3. Either pass the request through or block it (the enforcement)
func (t *TailscaleAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    // Step 1: Use our intelligent IP detection to find the real Tailscale client IP
    // This is where we handle the complexity of your networking setup
    clientIP := t.extractRealClientIP(req)
    
    // Step 2: Log our findings if debugging is enabled
    // This helps administrators understand what the plugin is seeing and deciding
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("Processing request to %s from detected IP: %s", req.URL.Path, clientIP))
    }
    
    // Step 3: Make the security decision - is this IP allowed?
    if t.isIPAllowed(clientIP) {
        // IP is allowed - grant access and continue to the next middleware or service
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("ALLOW: IP %s granted access", clientIP))
        }
        
        // Pass the request to the next handler in the chain
        t.next.ServeHTTP(rw, req)
        return
    }
    
    // Step 4: IP is not allowed - block access with a clear message
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("DENY: IP %s blocked (not in allowed ranges)", clientIP))
    }
    
    // Send HTTP 403 Forbidden with our custom message
    // This gives the user clear feedback about why they were blocked
    rw.WriteHeader(http.StatusForbidden)
    rw.Write([]byte(t.config.CustomErrorMessage))
}

// extractRealClientIP implements our intelligent IP detection logic
// This is the most complex part of the plugin because it needs to handle the reality
// of modern networking where the original client IP might be hidden behind multiple
// layers of proxies, load balancers, and container networking.
//
// The strategy is layered:
// 1. Check if the direct connection IP is already a Tailscale IP (simple case)
// 2. If not, systematically search through HTTP headers where proxies store the original IP
// 3. Return the first Tailscale IP we find, or the direct IP if none are found
func (t *TailscaleAuth) extractRealClientIP(req *http.Request) string {
    // Start with the direct connection IP
    // In simple setups, this might already be the Tailscale IP we're looking for
    directIP := t.getIPFromRemoteAddr(req.RemoteAddr)
    
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("Direct connection IP: %s", directIP))
    }
    
    // Quick win: if the direct IP is already a Tailscale IP, we're done
    // This handles the simple case where there's a direct Tailscale connection
    if t.isIPInTailscaleRange(directIP) {
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("Direct IP %s is in Tailscale range", directIP))
        }
        return directIP
    }
    
    // The direct IP isn't Tailscale, so now we need to search through headers
    // This is where we handle complex networking setups with proxies and container networking
    for _, header := range t.config.HeadersToCheck {
        headerValue := req.Header.Get(header)
        if headerValue == "" {
            continue // Skip empty headers
        }
        
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("Examining header %s: %s", header, headerValue))
        }
        
        // Headers often contain multiple IPs separated by commas
        // For example: "X-Forwarded-For: 100.64.1.100, 172.17.0.1, 10.0.0.1"
        // We need to check each IP to find the Tailscale one
        ips := strings.Split(headerValue, ",")
        for _, ip := range ips {
            cleanIP := strings.TrimSpace(ip)
            if t.isIPInTailscaleRange(cleanIP) {
                if t.config.EnableDebugLogging {
                    t.logDebug(fmt.Sprintf("Found Tailscale IP %s in header %s", cleanIP, header))
                }
                return cleanIP
            }
        }
    }
    
    // If we couldn't find a Tailscale IP anywhere, return the direct IP
    // This allows the security logic to properly evaluate and potentially reject the connection
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("No Tailscale IP found in headers, using direct IP: %s", directIP))
    }
    return directIP
}

// getIPFromRemoteAddr extracts the IP address from req.RemoteAddr
// RemoteAddr includes both IP and port (like "192.168.1.100:12345"), but we only want the IP
// This helper function safely extracts just the IP portion
func (t *TailscaleAuth) getIPFromRemoteAddr(remoteAddr string) string {
    host, _, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        // If we can't parse it as host:port, assume it's just an IP
        // This handles edge cases where the format might be unexpected
        return remoteAddr
    }
    return host
}

// isIPInTailscaleRange checks if an IP address falls within any configured Tailscale range
// This function implements the core logic for identifying Tailscale IPs by checking them
// against the configured CIDR ranges (like "100.64.0.0/10")
func (t *TailscaleAuth) isIPInTailscaleRange(ipStr string) bool {
    // Parse the IP string into a net.IP object for proper comparison
    ip := net.ParseIP(ipStr)
    if ip == nil {
        // Invalid IP format - can't be a valid Tailscale IP
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("Invalid IP format: %s", ipStr))
        }
        return false
    }
    
    // Check the IP against all configured Tailscale ranges
    for _, rangeStr := range t.config.TailscaleRanges {
        _, cidr, err := net.ParseCIDR(rangeStr)
        if err != nil {
            // Skip invalid CIDR ranges - log this as it indicates a configuration error
            if t.config.EnableDebugLogging {
                t.logDebug(fmt.Sprintf("Invalid CIDR range in config: %s", rangeStr))
            }
            continue
        }
        
        // Check if our IP falls within this CIDR range
        if cidr.Contains(ip) {
            if t.config.EnableDebugLogging {
                t.logDebug(fmt.Sprintf("IP %s matches Tailscale range %s", ipStr, rangeStr))
            }
            return true
        }
    }
    
    // IP doesn't match any Tailscale ranges
    return false
}

// isIPAllowed is the main authorization function that determines if an IP should be granted access
// This function implements the complete access control logic, checking both Tailscale ranges
// and any additional ranges (like localhost for development)
func (t *TailscaleAuth) isIPAllowed(ipStr string) bool {
    // Parse the IP for validation
    ip := net.ParseIP(ipStr)
    if ip == nil {
        // Invalid IP format - reject for safety
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("Rejecting invalid IP format: %s", ipStr))
        }
        return false
    }
    
    // First check if it's a Tailscale IP (the primary use case)
    if t.isIPInTailscaleRange(ipStr) {
        if t.config.EnableDebugLogging {
            t.logDebug(fmt.Sprintf("IP %s allowed (Tailscale range)", ipStr))
        }
        return true
    }
    
    // Check additional allowed ranges (like localhost for development/testing)
    for _, rangeStr := range t.config.AdditionalRanges {
        _, cidr, err := net.ParseCIDR(rangeStr)
        if err != nil {
            // Skip invalid CIDR ranges
            if t.config.EnableDebugLogging {
                t.logDebug(fmt.Sprintf("Invalid CIDR range in additional ranges: %s", rangeStr))
            }
            continue
        }
        
        if cidr.Contains(ip) {
            if t.config.EnableDebugLogging {
                t.logDebug(fmt.Sprintf("IP %s allowed (additional range %s)", ipStr, rangeStr))
            }
            return true
        }
    }
    
    // IP doesn't match any allowed ranges - deny access
    if t.config.EnableDebugLogging {
        t.logDebug(fmt.Sprintf("IP %s not in any allowed ranges", ipStr))
    }
    return false
}

// logDebug outputs debug information when debugging is enabled
// For Traefik plugins, we output to os.Stdout which gets captured by Traefik's logging system
// The format includes our middleware name to help identify which plugin instance generated the log
func (t *TailscaleAuth) logDebug(message string) {
    // Use a consistent format that's easy to grep and identify in logs
    logMessage := fmt.Sprintf("[TailscaleAuth:%s] %s\n", t.name, message)
    os.Stdout.WriteString(logMessage)
}