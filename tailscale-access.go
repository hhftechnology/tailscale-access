// Package tailscaleauth provides Tailscale-aware IP authentication for Traefik
package tailscale_access

import (
	"context"
	"fmt"
	"log" // Using log package for more standard logging output
	"net"
	"net/http"
	"strings"
)

const (
	// DefaultTailscaleCIDR is the common Class G Network (CGNAT) range used by Tailscale.
	DefaultTailscaleCIDR = "100.64.0.0/10"
	// DefaultErrorMessage is the message shown to users when access is denied.
	DefaultErrorMessage = "Access denied: Tailscale connection required"
)

// DefaultHeadersToCheck are the HTTP headers commonly used to convey the original client IP address.
var DefaultHeadersToCheck = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Original-Forwarded-For", // Common in some proxy setups
	"CF-Connecting-IP",         // Cloudflare
	"True-Client-IP",           // Akamai and Cloudflare
	"X-Client-IP",              // Common alternative
	// Add other headers if your specific setup uses them
}

// Config represents the configuration options for the Tailscale authentication plugin.
type Config struct {
	// TailscaleRanges defines the IP CIDR ranges that should be considered as Tailscale networks.
	// Defaults to ["100.64.0.0/10"] if empty.
	TailscaleRanges []string `json:"tailscaleRanges,omitempty"`

	// AdditionalRanges allows specifying other IP CIDR ranges that should also be granted access.
	// Useful for allowing access from local networks or specific trusted IPs.
	AdditionalRanges []string `json:"additionalRanges,omitempty"`

	// HeadersToCheck specifies which HTTP headers should be inspected to find the client's real IP address.
	// Order matters: headers are checked in the order they are listed.
	// Defaults to a list of common headers like "X-Forwarded-For", "X-Real-IP", etc.
	HeadersToCheck []string `json:"headersToCheck,omitempty"`

	// EnableDebugLogging, if true, will print detailed logs about IP checking.
	EnableDebugLogging bool `json:"enableDebugLogging,omitempty"`

	// CustomErrorMessage is the message displayed to users when access is denied.
	// Defaults to "Access denied: Tailscale connection required".
	CustomErrorMessage string `json:"customErrorMessage,omitempty"`
}

// CreateConfig creates a default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TailscaleRanges:    []string{DefaultTailscaleCIDR},
		HeadersToCheck:     DefaultHeadersToCheck,
		EnableDebugLogging: false,
		CustomErrorMessage: DefaultErrorMessage,
		AdditionalRanges:   []string{}, // Explicitly empty by default
	}
}

// TailscaleAuth is the middleware instance.
type TailscaleAuth struct {
	next               http.Handler
	name               string
	config             *Config
	parsedTailscaleNets []*net.IPNet
	parsedAdditionalNets []*net.IPNet
}

// New creates a new instance of the Tailscale authentication middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Apply defaults if certain configuration fields are empty
	if len(config.TailscaleRanges) == 0 {
		config.TailscaleRanges = []string{DefaultTailscaleCIDR}
	}
	if len(config.HeadersToCheck) == 0 {
		config.HeadersToCheck = DefaultHeadersToCheck
	}
	if config.CustomErrorMessage == "" {
		config.CustomErrorMessage = DefaultErrorMessage
	}

	// Pre-parse CIDR ranges for efficiency
	parsedTailscaleNets, err := parseCIDRs(config.TailscaleRanges)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tailscaleRanges: %w", err)
	}

	parsedAdditionalNets, err := parseCIDRs(config.AdditionalRanges)
	if err != nil {
		return nil, fmt.Errorf("failed to parse additionalRanges: %w", err)
	}

	if len(parsedTailscaleNets) == 0 && len(parsedAdditionalNets) == 0 {
		return nil, fmt.Errorf("tailscale-auth plugin misconfiguration: at least one valid TailscaleRange or AdditionalRange must be provided")
	}

	if config.EnableDebugLogging {
		log.Printf("[INFO] TailscaleAuth plugin '%s' initialized. Tailscale Ranges: %v, Additional Ranges: %v, Headers: %v",
			name, config.TailscaleRanges, config.AdditionalRanges, config.HeadersToCheck)
	}

	return &TailscaleAuth{
		next:                 next,
		name:                 name,
		config:               config,
		parsedTailscaleNets:  parsedTailscaleNets,
		parsedAdditionalNets: parsedAdditionalNets,
	}, nil
}

// parseCIDRs converts a slice of CIDR strings to a slice of *net.IPNet.
func parseCIDRs(cidrStrings []string) ([]*net.IPNet, error) {
	parsedNets := make([]*net.IPNet, 0, len(cidrStrings))
	for _, cidrStr := range cidrStrings {
		if cidrStr == "" {
			continue // Skip empty strings
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR string %q: %w", cidrStr, err)
		}
		parsedNets = append(parsedNets, ipNet)
	}
	return parsedNets, nil
}

// ServeHTTP processes each incoming request, checking for Tailscale IP authentication.
func (t *TailscaleAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIPStr := t.extractClientIP(req)
	if clientIPStr == "" {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': No client IP found for request to %s", t.name, req.URL.Path)
		}
		t.denyAccess(rw)
		return
	}

	clientIP := net.ParseIP(clientIPStr)
	if clientIP == nil {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Invalid client IP format '%s' for request to %s", t.name, clientIPStr, req.URL.Path)
		}
		t.denyAccess(rw)
		return
	}

	if t.config.EnableDebugLogging {
		log.Printf("[DEBUG] TailscaleAuth '%s': Checking IP %s (parsed from %s) for request to %s", t.name, clientIP.String(), clientIPStr, req.URL.Path)
	}

	if t.isIPAllowed(clientIP) {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Allowing access for IP %s", t.name, clientIP.String())
		}
		t.next.ServeHTTP(rw, req)
		return
	}

	if t.config.EnableDebugLogging {
		log.Printf("[DEBUG] TailscaleAuth '%s': Blocking access for IP %s", t.name, clientIP.String())
	}
	t.denyAccess(rw)
}

// extractClientIP attempts to find the client's real IP address.
// It checks specified HTTP headers first, then falls back to the request's RemoteAddr.
func (t *TailscaleAuth) extractClientIP(req *http.Request) string {
	// Check headers first
	for _, headerName := range t.config.HeadersToCheck {
		headerValue := req.Header.Get(headerName)
		if headerValue == "" {
			continue
		}

		// Headers like X-Forwarded-For can contain a list of IPs.
		// We are interested in the first *valid* IP in the list that might be a Tailscale IP.
		// Typically, the first IP in XFF is the original client.
		ips := strings.Split(headerValue, ",")
		for _, ipStr := range ips {
			trimmedIP := strings.TrimSpace(ipStr)
			// Quick check: if this IP is in a Tailscale range, use it.
			// This avoids unnecessary parsing of RemoteAddr if a header IP is already confirmed.
			// Note: We re-parse here, but the primary check is in isIPAllowed with parsed nets.
			// This is a heuristic to pick the "best" IP from headers.
			if net.ParseIP(trimmedIP) != nil { // Ensure it's a valid IP format before deeper checks
				if t.isIPInSpecificNets(net.ParseIP(trimmedIP), t.parsedTailscaleNets) {
					if t.config.EnableDebugLogging {
						log.Printf("[DEBUG] TailscaleAuth '%s': Found potential Tailscale IP %s in header %s: %s", t.name, trimmedIP, headerName, headerValue)
					}
					return trimmedIP // Found a Tailscale IP in a header
				}
				// If not a Tailscale IP, but it's the first one in the list, it's a candidate.
				// The actual decision will be made by isIPAllowed.
				// We prefer the first IP from the first populated header.
				if t.config.EnableDebugLogging {
					log.Printf("[DEBUG] TailscaleAuth '%s': Using first IP %s from header %s: %s as candidate", t.name, trimmedIP, headerName, headerValue)
				}
				return trimmedIP
			}
		}
	}

	// Fallback to RemoteAddr if no suitable IP found in headers
	directIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If RemoteAddr is not in host:port format, use it as is (could be just an IP)
		if t.config.EnableDebugLogging && req.RemoteAddr != "" {
			log.Printf("[DEBUG] TailscaleAuth '%s': Could not split host/port for RemoteAddr '%s', using as is. Error: %v", t.name, req.RemoteAddr, err)
		}
		return strings.TrimSpace(req.RemoteAddr)
	}
	if t.config.EnableDebugLogging && directIP != "" {
		log.Printf("[DEBUG] TailscaleAuth '%s': Using IP %s from RemoteAddr", t.name, directIP)
	}
	return strings.TrimSpace(directIP)
}

// isIPAllowed checks if the given IP address is present in any of the configured Tailscale or additional CIDR ranges.
func (t *TailscaleAuth) isIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Check against Tailscale ranges first
	if t.isIPInSpecificNets(ip, t.parsedTailscaleNets) {
		return true
	}
	// Then check against additional allowed ranges
	return t.isIPInSpecificNets(ip, t.parsedAdditionalNets)
}

// isIPInSpecificNets checks if an IP is contained within any of the provided IP networks.
func (t *TailscaleAuth) isIPInSpecificNets(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// denyAccess sends a 403 Forbidden response with the custom error message.
func (t *TailscaleAuth) denyAccess(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "text/plain")
	rw.WriteHeader(http.StatusForbidden)
	_, err := rw.Write([]byte(t.config.CustomErrorMessage))
	if err != nil {
		if t.config.EnableDebugLogging {
			log.Printf("[ERROR] TailscaleAuth '%s': Failed to write response body: %v", t.name, err)
		}
	}
}