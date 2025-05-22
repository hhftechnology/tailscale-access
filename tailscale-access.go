// Enhanced version that detects Tailscale connections more intelligently
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
	DefaultTailscaleCIDR = "100.64.0.0/10"
	DefaultErrorMessage  = "Access denied: Tailscale connection required"
)

var DefaultHeadersToCheck = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Original-Forwarded-For",
	"CF-Connecting-IP",
	"True-Client-IP",
	"X-Client-IP",
	"Tailscale-User",      // Tailscale sets this header
	"Tailscale-Login",     // Additional Tailscale header
}

type Config struct {
	TailscaleRanges    []string `json:"tailscaleRanges,omitempty"`
	AdditionalRanges   []string `json:"additionalRanges,omitempty"`
	HeadersToCheck     []string `json:"headersToCheck,omitempty"`
	EnableDebugLogging bool     `json:"enableDebugLogging,omitempty"`
	CustomErrorMessage string   `json:"customErrorMessage,omitempty"`
	StrictMode         bool     `json:"strictMode,omitempty"`
	TrustedProxies     []string `json:"trustedProxies,omitempty"`
	
	// New: Detect Tailscale by interface/route
	AutoDetectTailscale bool   `json:"autoDetectTailscale,omitempty"`
	
	// New: Allow bypass for localhost development
	AllowLocalhost     bool   `json:"allowLocalhost,omitempty"`
	
	// New: Show helpful error with Tailscale connection instructions
	ShowTailscaleHelp  bool   `json:"showTailscaleHelp,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TailscaleRanges:     []string{DefaultTailscaleCIDR},
		HeadersToCheck:      DefaultHeadersToCheck,
		EnableDebugLogging:  false,
		CustomErrorMessage:  DefaultErrorMessage,
		AdditionalRanges:    []string{},
		StrictMode:          true,
		TrustedProxies:      []string{},
		AutoDetectTailscale: true,  // New default
		AllowLocalhost:      true,  // Allow localhost for development
		ShowTailscaleHelp:   true,  // Show helpful error messages
	}
}

type TailscaleAuth struct {
	next                 http.Handler
	name                 string
	config               *Config
	parsedTailscaleNets  []*net.IPNet
	parsedAdditionalNets []*net.IPNet
	parsedTrustedProxies []*net.IPNet
	localTailscaleIP     net.IP // Detected local Tailscale IP
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Apply defaults
	if len(config.TailscaleRanges) == 0 {
		config.TailscaleRanges = []string{DefaultTailscaleCIDR}
	}
	if len(config.HeadersToCheck) == 0 {
		config.HeadersToCheck = DefaultHeadersToCheck
	}
	if config.CustomErrorMessage == "" {
		config.CustomErrorMessage = DefaultErrorMessage
	}

	// Parse CIDR ranges
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

	// Auto-detect local Tailscale IP
	var localTailscaleIP net.IP
	if config.AutoDetectTailscale {
		localTailscaleIP = detectLocalTailscaleIP(parsedTailscaleNets)
		if localTailscaleIP != nil && config.EnableDebugLogging {
			log.Printf("[INFO] TailscaleAuth '%s': Detected local Tailscale IP: %s", name, localTailscaleIP.String())
		}
	}

	if len(parsedTailscaleNets) == 0 && len(parsedAdditionalNets) == 0 {
		return nil, fmt.Errorf("tailscale-auth plugin misconfiguration: at least one valid TailscaleRange or AdditionalRange must be provided")
	}

	if config.EnableDebugLogging {
		log.Printf("[INFO] TailscaleAuth plugin '%s' initialized. Tailscale Ranges: %v, Additional Ranges: %v, LocalTailscaleIP: %v", 
			name, config.TailscaleRanges, config.AdditionalRanges, localTailscaleIP)
	}

	return &TailscaleAuth{
		next:                 next,
		name:                 name,
		config:               config,
		parsedTailscaleNets:  parsedTailscaleNets,
		parsedAdditionalNets: parsedAdditionalNets,
		parsedTrustedProxies: parsedTrustedProxies,
		localTailscaleIP:     localTailscaleIP,
	}, nil
}

// detectLocalTailscaleIP tries to find the local Tailscale IP
func detectLocalTailscaleIP(tailscaleNets []*net.IPNet) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		// Skip non-Tailscale interfaces
		if !strings.Contains(strings.ToLower(iface.Name), "tailscale") && 
		   !strings.Contains(strings.ToLower(iface.Name), "utun") &&
		   !strings.Contains(strings.ToLower(iface.Name), "tun") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP
				// Check if this IP is in Tailscale range
				for _, tailscaleNet := range tailscaleNets {
					if tailscaleNet.Contains(ip) {
						return ip
					}
				}
			}
		}
	}
	return nil
}

func parseCIDRs(cidrStrings []string) ([]*net.IPNet, error) {
	parsedNets := make([]*net.IPNet, 0, len(cidrStrings))
	for _, cidrStr := range cidrStrings {
		if cidrStr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR string %q: %w", cidrStr, err)
		}
		parsedNets = append(parsedNets, ipNet)
	}
	return parsedNets, nil
}

func (t *TailscaleAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP, source := t.extractClientIP(req)
	if clientIP == nil {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': No valid client IP found for request to %s", t.name, req.URL.Path)
		}
		t.denyAccess(rw, req)
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
	t.denyAccess(rw, req)
}

func (t *TailscaleAuth) extractClientIP(req *http.Request) (net.IP, string) {
	// Check for Tailscale-specific headers first
	if tailscaleUser := req.Header.Get("Tailscale-User"); tailscaleUser != "" {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Found Tailscale-User header: %s", t.name, tailscaleUser)
		}
		// If we have Tailscale headers, trust that this is a Tailscale connection
		// and use the local Tailscale IP
		if t.localTailscaleIP != nil {
			return t.localTailscaleIP, "Tailscale-User header (local TS IP)"
		}
	}

	// Get direct connection IP
	directIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		directIP = strings.TrimSpace(req.RemoteAddr)
	}
	directIPParsed := net.ParseIP(strings.TrimSpace(directIP))

	// Check if we should trust headers from this direct connection
	trustHeaders := len(t.parsedTrustedProxies) == 0 || 
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

		ips := strings.Split(headerValue, ",")
		for i, ipStr := range ips {
			trimmedIP := strings.TrimSpace(ipStr)
			parsedIP := net.ParseIP(trimmedIP)
			if parsedIP == nil {
				continue
			}

			if t.config.StrictMode {
				if t.isIPInSpecificNets(parsedIP, t.parsedTailscaleNets) {
					if t.config.EnableDebugLogging {
						log.Printf("[DEBUG] TailscaleAuth '%s': Found Tailscale IP %s in header %s (position %d)", t.name, trimmedIP, headerName, i)
					}
					return parsedIP, fmt.Sprintf("header %s (strict mode)", headerName)
				}
				continue
			}

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

func (t *TailscaleAuth) isIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Special case: allow localhost if configured
	if t.config.AllowLocalhost && ip.IsLoopback() {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': Allowing localhost IP %s", t.name, ip.String())
		}
		return true
	}

	// Check against Tailscale ranges first
	if t.isIPInSpecificNets(ip, t.parsedTailscaleNets) {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': IP %s matches Tailscale range", t.name, ip.String())
		}
		return true
	}

	// Check against additional allowed ranges
	if t.isIPInSpecificNets(ip, t.parsedAdditionalNets) {
		if t.config.EnableDebugLogging {
			log.Printf("[DEBUG] TailscaleAuth '%s': IP %s matches additional range", t.name, ip.String())
		}
		return true
	}

	return false
}

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

func (t *TailscaleAuth) denyAccess(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusForbidden)
	
	if t.config.ShowTailscaleHelp {
		helpMessage := t.generateHelpMessage(req)
		_, err := rw.Write([]byte(helpMessage))
		if err != nil && t.config.EnableDebugLogging {
			log.Printf("[ERROR] TailscaleAuth '%s': Failed to write response body: %v", t.name, err)
		}
	} else {
		_, err := rw.Write([]byte(t.config.CustomErrorMessage))
		if err != nil && t.config.EnableDebugLogging {
			log.Printf("[ERROR] TailscaleAuth '%s': Failed to write response body: %v", t.name, err)
		}
	}
}

func (t *TailscaleAuth) generateHelpMessage(req *http.Request) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Tailscale Connection Required</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; }
        .help { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin-top: 20px; }
        code { background: #f8f9fa; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="error">
        <h2>🔒 Access Denied</h2>
        <p>This service requires a Tailscale connection.</p>
    </div>
    
    <div class="help">
        <h3>How to access this service:</h3>
        <ol>
            <li><strong>Install Tailscale:</strong> Visit <a href="https://tailscale.com/download">tailscale.com/download</a></li>
            <li><strong>Connect to your network:</strong> Join the Tailscale network</li>
            <li><strong>Refresh this page</strong></li>
        </ol>
        
        <p><strong>Service:</strong> %s</p>
        <p><strong>Your IP:</strong> Not from Tailscale network</p>
        
        <details>
            <summary>Technical Details</summary>
            <p>This service is protected by Tailscale network access control. Only devices connected to the Tailscale network can access this resource.</p>
        </details>
    </div>
</body>
</html>`, req.Host)
}