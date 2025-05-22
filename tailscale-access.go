// Package tailscale_access provides Tailscale-aware IP authentication for Traefik
package tailscale_access

import (
	"context"
	"fmt"
	"log"
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

	// StrictMode, if true, only allows IPs from headers if they're Tailscale IPs.
	// This prevents header spoofing attacks. Defaults to true for security.
	StrictMode bool `json:"strictMode,omitempty"`

	// TrustedProxies defines CIDR ranges of trusted proxies that are allowed to set forwarding headers.
	// If empty, headers from any source are trusted (less secure).
	TrustedProxies []string `json:"trustedProxies,omitempty"`
}

// CreateConfig creates a default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TailscaleRanges:    []string{DefaultTailscaleCIDR},
		HeadersToCheck:     DefaultHeadersToCheck,
		EnableDebugLogging: false,
		CustomErrorMessage: DefaultErrorMessage,
		AdditionalRanges:   []string{}, // Explicitly empty by default
		StrictMode:         true,       // Enable strict mode by default for security
		TrustedProxies:     []string{}, // No trusted proxies by default
	}
}

// TailscaleAuth is the middleware instance.
type TailscaleAuth struct {
	next                 http.Handler
	name                 string
	config               *Config
	parsedTailscaleNets  []*net.IPNet
	parsedAdditionalNets []*net.IPNet
	parsedTrustedProxies []*net.IPNet
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

	parsedTrustedProxies, err := parseCIDRs(config.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trustedProxies: %w", err)
	}

	if len(parsedTailscaleNets) == 0 && len(parsedAdditionalNets) == 0 {
		return nil, fmt.Errorf("tailscale-auth plugin misconfiguration: at least one valid TailscaleRange or AdditionalRange must be provided")
	}

	if config.EnableDebugLogging {
		log.Printf("[INFO] TailscaleAuth plugin '%s' initialized. Tailscale Ranges: %v, Additional Ranges: %v, Headers: %v, StrictMode: %v",
			name, config.TailscaleRanges, config.AdditionalRanges, config.HeadersToCheck, config.StrictMode)
	}

	return &TailscaleAuth{
		next:                 next,
		name:                 name,
		config:               config,
		parsedTailscaleNets:  parsedTailscaleNets,
		parsedAdditionalNets: parsedAdditionalNets,
		parsedTrustedProxies: parsedTrustedProxies,
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
	clientIP, source := t.extractClientIP(req)
	if clientIP == nil {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': No valid client IP found for request to %s", t.name, req.URL.Path)
		}
		t.denyAccess(rw)
		return
	}

	if t.config.EnableDebugLogging {
		log.Printf("[DEBUG] TailscaleAuth '%s': Checking IP %s (from %s) for request to %s", t.name, clientIP.String(), source, req.URL.Path)
	}

	if t.isIPAllowed(clientIP) {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Allowing access for IP %s (from %s)", t.name, clientIP.String(), source)
		}
		t.next.ServeHTTP(rw, req)
		return
	}

	if t.config.EnableDebugLogging {
		log.Printf("[DEBUG] TailscaleAuth '%s': Blocking access for IP %s (from %s)", t.name, clientIP.String(), source)
	}
	t.denyAccess(rw)
}

// extractClientIP attempts to find the client's real IP address with improved security.
// Returns the IP and a description of where it was found.
func (t *TailscaleAuth) extractClientIP(req *http.Request) (net.IP, string) {
	// Get the direct connection IP first
	directIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If RemoteAddr is not in host:port format, use it as is
		directIP = strings.TrimSpace(req.RemoteAddr)
	}
	directIPParsed := net.ParseIP(strings.TrimSpace(directIP))

	// Check if we should trust headers from this direct connection
	trustHeaders := len(t.parsedTrustedProxies) == 0 || // No trusted proxies configured (trust all)
		(directIPParsed != nil && t.isIPInSpecificNets(directIPParsed, t.parsedTrustedProxies))

	if !trustHeaders {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Direct IP %s is not in trusted proxies, ignoring headers", t.name, directIP)
		}
		return directIPParsed, "RemoteAddr (untrusted proxy)"
	}

	// Check headers for forwarded IPs
	for _, headerName := range t.config.HeadersToCheck {
		headerValue := req.Header.Get(headerName)
		if headerValue == "" {
			continue
		}

		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Checking header %s: %s", t.name, headerName, headerValue)
		}

		// Headers like X-Forwarded-For can contain a list of IPs
		ips := strings.Split(headerValue, ",")
		for i, ipStr := range ips {
			trimmedIP := strings.TrimSpace(ipStr)
			parsedIP := net.ParseIP(trimmedIP)
			if parsedIP == nil {
				continue // Skip invalid IPs
			}

			// In strict mode, only return header IPs if they're in Tailscale ranges
			if t.config.StrictMode {
				if t.isIPInSpecificNets(parsedIP, t.parsedTailscaleNets) {
					if t.config.EnableDebugLogging {
						log.Printf("[DEBUG] TailscaleAuth '%s': Found Tailscale IP %s in header %s (position %d)", t.name, trimmedIP, headerName, i)
					}
					return parsedIP, fmt.Sprintf("header %s (strict mode)", headerName)
				}
				// In strict mode, continue looking for Tailscale IPs
				continue
			}

			// In non-strict mode, return the first valid IP (for backward compatibility)
			if t.config.EnableDebugLogging {
				log.Printf("[DEBUG] TailscaleAuth '%s': Using IP %s from header %s (position %d, non-strict mode)", t.name, trimmedIP, headerName, i)
			}
			return parsedIP, fmt.Sprintf("header %s (non-strict mode)", headerName)
		}
	}

	// Fallback to direct connection IP
	if directIPParsed != nil {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Using direct connection IP %s", t.name, directIP)
		}
		return directIPParsed, "RemoteAddr (fallback)"
	}

	return nil, "none found"
}

// isIPAllowed checks if the given IP address is present in any of the configured Tailscale or additional CIDR ranges.
func (t *TailscaleAuth) isIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check against Tailscale ranges first
	if t.isIPInSpecificNets(ip, t.parsedTailscaleNets) {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': IP %s matches Tailscale range", t.name, ip.String())
		}
		return true
	}

	// Then check against additional allowed ranges
	if t.isIPInSpecificNets(ip, t.parsedAdditionalNets) {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': IP %s matches additional range", t.name, ip.String())
		}
		return true
	}

	return false
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