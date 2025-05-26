// Tailscale Authentication Plugin - Connectivity Based Verification
package tailscale_access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	// Tailscale domain to test connectivity against
	TestDomain string `json:"testDomain,omitempty"`
	
	// Custom verification endpoint (optional)
	VerificationEndpoint string `json:"verificationEndpoint,omitempty"`
	
	// Session timeout for verified connections (in seconds)
	SessionTimeoutSeconds int `json:"sessionTimeoutSeconds,omitempty"`
	
	// Session timeout as duration string (e.g., "24h", "30m") - will be converted to seconds
	SessionTimeout string `json:"sessionTimeout,omitempty"`
	
	// Custom error messages
	CustomErrorMessage string `json:"customErrorMessage,omitempty"`
	SuccessMessage     string `json:"successMessage,omitempty"`
	
	// Enable debug logging
	EnableDebugLogging bool `json:"enableDebugLogging,omitempty"`
	
	// Bypass for development
	AllowLocalhost bool `json:"allowLocalhost,omitempty"`
	
	// Custom styling
	CustomCSS    string `json:"customCSS,omitempty"`
	CustomScript string `json:"customScript,omitempty"`
	
	// Security settings
	SecureOnly        bool   `json:"secureOnly,omitempty"`
	CookieDomain      string `json:"cookieDomain,omitempty"`
	RequireUserAgent  bool   `json:"requireUserAgent,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TestDomain:            "your-tailscale-network.ts.net", // User should configure this
		SessionTimeout:        "24h",
		SessionTimeoutSeconds: 86400, // 24 hours in seconds as fallback
		CustomErrorMessage:    "Tailscale connection required to access this service",
		SuccessMessage:        "Tailscale connectivity verified! Redirecting...",
		EnableDebugLogging:    false,
		AllowLocalhost:        true,
		SecureOnly:            true,
		RequireUserAgent:      true,
	}
}

type TailscaleConnectivityAuth struct {
	next            http.Handler
	name            string
	config          *Config
	sessionTimeout  time.Duration // Parsed duration for internal use
	secrets         map[string]time.Time // Simple in-memory session store
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Apply defaults and validate
	if config.TestDomain == "" {
		return nil, fmt.Errorf("testDomain must be configured")
	}
	
	// Parse session timeout
	var sessionTimeout time.Duration
	var err error
	
	if config.SessionTimeout != "" {
		// Try to parse duration string (e.g., "24h", "30m")
		sessionTimeout, err = time.ParseDuration(config.SessionTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid sessionTimeout format: %v (use format like '24h', '30m', '45s')", err)
		}
	} else if config.SessionTimeoutSeconds > 0 {
		// Use seconds if provided
		sessionTimeout = time.Duration(config.SessionTimeoutSeconds) * time.Second
	} else {
		// Default to 24 hours
		sessionTimeout = 24 * time.Hour
	}
	
	// Apply other defaults
	if config.CustomErrorMessage == "" {
		config.CustomErrorMessage = "Tailscale connection required to access this service"
	}
	if config.SuccessMessage == "" {
		config.SuccessMessage = "Tailscale connectivity verified! Redirecting..."
	}

	return &TailscaleConnectivityAuth{
		next:           next,
		name:           name,
		config:         config,
		sessionTimeout: sessionTimeout,
		secrets:        make(map[string]time.Time),
	}, nil
}

func (t *TailscaleConnectivityAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check for localhost bypass
	if t.config.AllowLocalhost && t.isLocalhost(req) {
		t.next.ServeHTTP(rw, req)
		return
	}

	// Handle verification callback
	if req.URL.Path == "/__tailscale_verify" {
		t.handleVerification(rw, req)
		return
	}

	// Check if already verified
	if t.isVerified(req) {
		t.next.ServeHTTP(rw, req)
		return
	}

	// Show verification page
	t.serveVerificationPage(rw, req)
}

func (t *TailscaleConnectivityAuth) isLocalhost(req *http.Request) bool {
	host := req.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (t *TailscaleConnectivityAuth) isVerified(req *http.Request) bool {
	cookie, err := req.Cookie("tailscale_verified")
	if err != nil {
		return false
	}

	// Check if token exists and is not expired
	expiry, exists := t.secrets[cookie.Value]
	if !exists || time.Now().After(expiry) {
		// Clean up expired token
		delete(t.secrets, cookie.Value)
		return false
	}

	return true
}

func (t *TailscaleConnectivityAuth) handleVerification(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := req.ParseForm(); err != nil {
		http.Error(rw, "Invalid form data", http.StatusBadRequest)
		return
	}

	status := req.FormValue("status")
	originalURL := req.FormValue("originalURL")

	if status == "success" {
		// Generate verification token
		token := t.generateToken()
		expiry := time.Now().Add(t.sessionTimeout)
		t.secrets[token] = expiry

		// Set secure cookie
		cookie := &http.Cookie{
			Name:     "tailscale_verified",
			Value:    token,
			Expires:  expiry,
			HttpOnly: true,
			Secure:   t.config.SecureOnly,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		}
		if t.config.CookieDomain != "" {
			cookie.Domain = t.config.CookieDomain
		}
		http.SetCookie(rw, cookie)

		// Return success response
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"success": true, "message": "%s", "redirectURL": "%s"}`, 
			t.config.SuccessMessage, originalURL)
		rw.Write([]byte(response))
		return
	}

	// Verification failed
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusForbidden)
	response := fmt.Sprintf(`{"success": false, "message": "%s"}`, t.config.CustomErrorMessage)
	rw.Write([]byte(response))
}

func (t *TailscaleConnectivityAuth) generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

func (t *TailscaleConnectivityAuth) serveVerificationPage(rw http.ResponseWriter, req *http.Request) {
	// Get the original URL for redirect after verification
	originalURL := req.URL.String()
	if req.URL.RawQuery != "" {
		originalURL = req.URL.Path + "?" + req.URL.RawQuery
	} else {
		originalURL = req.URL.Path
	}

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)

	html := t.generateVerificationHTML(originalURL)
	rw.Write([]byte(html))
}

func (t *TailscaleConnectivityAuth) generateVerificationHTML(originalURL string) string {
	customCSS := t.config.CustomCSS
	if customCSS == "" {
		customCSS = t.getDefaultCSS()
	}

	customScript := t.config.CustomScript
	if customScript == "" {
		customScript = ""
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tailscale Verification Required</title>
    <style>%s</style>
</head>
<body>
    <div class="container">
        <div class="verification-card">
            <div class="header">
                <div class="tailscale-logo">
                    <svg width="40" height="40" viewBox="0 0 100 100" fill="none">
                        <circle cx="50" cy="50" r="45" fill="#000"/>
                        <path d="M25 35h50v30H25z" fill="#fff"/>
                        <circle cx="35" cy="50" r="5" fill="#000"/>
                        <circle cx="65" cy="50" r="5" fill="#000"/>
                    </svg>
                </div>
                <h1>Tailscale Verification</h1>
                <p>Verifying your Tailscale connection...</p>
            </div>

            <div class="status-container">
                <div id="checking" class="status-item active">
                    <div class="spinner"></div>
                    <span>Testing Tailscale connectivity...</span>
                </div>
                
                <div id="success" class="status-item success hidden">
                    <div class="check-icon">✓</div>
                    <span>Tailscale connection verified!</span>
                </div>
                
                <div id="error" class="status-item error hidden">
                    <div class="error-icon">✗</div>
                    <span>Tailscale connection not detected</span>
                </div>
            </div>

            <div id="error-details" class="error-details hidden">
                <h3>How to connect via Tailscale:</h3>
                <ol>
                    <li><strong>Install Tailscale</strong> from <a href="https://tailscale.com/download" target="_blank">tailscale.com/download</a></li>
                    <li><strong>Connect to your network</strong> and ensure you can access <code>%s</code></li>
                    <li><strong>Refresh this page</strong> to try again</li>
                </ol>
                
                <div class="technical-details">
                    <details>
                        <summary>Technical Details</summary>
                        <p>This service requires access through a Tailscale network. We test connectivity by attempting to reach your Tailscale domain.</p>
                        <p><strong>Test Domain:</strong> <code>%s</code></p>
                        <p><strong>Error:</strong> <span id="error-message">Connection failed</span></p>
                    </details>
                </div>
                
                <button onclick="retryVerification()" class="retry-button">
                    <span class="retry-icon">↻</span>
                    Try Again
                </button>
            </div>

            <div id="success-details" class="success-details hidden">
                <p>%s</p>
                <div class="progress-bar">
                    <div class="progress-fill"></div>
                </div>
                <p class="redirect-text">Redirecting in <span id="countdown">3</span> seconds...</p>
            </div>
        </div>
    </div>

    <script>
        let verificationAttempts = 0;
        const maxAttempts = 3;
        const testDomain = '%s';
        const originalURL = '%s';

        %s

        async function verifyTailscaleConnectivity() {
            verificationAttempts++;
            
            try {
                // Test 1: Try HTTP first (more reliable for Tailscale domains)
                const httpUrl = 'http://' + testDomain + '/';
                
                const controllerHttp = new AbortController();
                const timeoutIdHttp = setTimeout(() => controllerHttp.abort(), 5000);
                
                const httpResponse = await fetch(httpUrl, {
                    method: 'GET',
                    mode: 'no-cors',
                    cache: 'no-cache',
                    signal: controllerHttp.signal
                });
                
                clearTimeout(timeoutIdHttp);
                await reportVerificationResult(true, 'Tailscale domain reachable via HTTP');
                
            } catch (httpError) {
                console.log('HTTP test failed:', httpError.message);
                
                // Test 2: Try HTTPS fallback
                try {
                    const httpsUrl = 'https://' + testDomain + '/';
                    const controllerHttps = new AbortController();
                    const timeoutIdHttps = setTimeout(() => controllerHttps.abort(), 5000);
                    
                    const httpsResponse = await fetch(httpsUrl, {
                        method: 'GET',
                        mode: 'no-cors',
                        cache: 'no-cache',
                        signal: controllerHttps.signal
                    });
                    
                    clearTimeout(timeoutIdHttps);
                    await reportVerificationResult(true, 'Tailscale domain reachable via HTTPS');
                    
                } catch (httpsError) {
                    console.log('HTTPS test failed:', httpsError.message);
                    
                    // Test 3: Try image loading with HTTP first
                    try {
                        await testImageLoad();
                        await reportVerificationResult(true, 'Tailscale connectivity confirmed via image test');
                    } catch (imgError) {
                        console.log('Image test failed:', imgError.message);
                        await reportVerificationResult(false, 'All connectivity tests failed. HTTP: ' + httpError.message + ', HTTPS: ' + httpsError.message);
                    }
                }
            }
        }

        function testImageLoad() {
            return new Promise((resolve, reject) => {
                // Try HTTP first (more reliable for Tailscale)
                const img = new Image();
                const timeout = setTimeout(() => {
                    reject(new Error('Image load timeout'));
                }, 5000);
                
                img.onload = () => {
                    clearTimeout(timeout);
                    resolve();
                };
                
                img.onerror = () => {
                    clearTimeout(timeout);
                    // Try HTTPS fallback
                    const img2 = new Image();
                    const timeout2 = setTimeout(() => {
                        reject(new Error('Image load failed (both HTTP and HTTPS)'));
                    }, 3000);
                    
                    img2.onload = () => {
                        clearTimeout(timeout2);
                        resolve();
                    };
                    
                    img2.onerror = () => {
                        clearTimeout(timeout2);
                        reject(new Error('Image load failed (both HTTP and HTTPS)'));
                    };
                    
                    // Try HTTPS as fallback
                    img2.src = 'https://' + testDomain + '/favicon.ico?t=' + Date.now();
                };
                
                // Try HTTP first
                img.src = 'http://' + testDomain + '/favicon.ico?t=' + Date.now();
            });
        }

        function testWebSocket() {
            return new Promise((resolve, reject) => {
                try {
                    const ws = new WebSocket('wss://' + testDomain + '/ws');
                    const timeout = setTimeout(() => {
                        ws.close();
                        reject(new Error('WebSocket timeout'));
                    }, 3000);
                    
                    ws.onopen = () => {
                        clearTimeout(timeout);
                        ws.close();
                        resolve();
                    };
                    
                    ws.onerror = () => {
                        clearTimeout(timeout);
                        reject(new Error('WebSocket connection failed'));
                    };
                } catch (error) {
                    reject(error);
                }
            });
        }

        async function reportVerificationResult(success, message) {
            const formData = new FormData();
            formData.append('status', success ? 'success' : 'failure');
            formData.append('originalURL', originalURL);
            formData.append('message', message);

            try {
                const response = await fetch('/__tailscale_verify', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (success && result.success) {
                    showSuccess();
                    setTimeout(() => {
                        window.location.href = originalURL;
                    }, 3000);
                } else {
                    showError(message);
                }
            } catch (error) {
                console.error('Failed to report verification result:', error);
                showError('Verification reporting failed: ' + error.message);
            }
        }

        function showSuccess() {
            document.getElementById('checking').classList.remove('active');
            document.getElementById('checking').classList.add('hidden');
            document.getElementById('success').classList.remove('hidden');
            document.getElementById('success').classList.add('active');
            document.getElementById('success-details').classList.remove('hidden');
            
            // Start countdown
            let countdown = 3;
            const countdownElement = document.getElementById('countdown');
            const countdownTimer = setInterval(() => {
                countdown--;
                countdownElement.textContent = countdown;
                if (countdown <= 0) {
                    clearInterval(countdownTimer);
                }
            }, 1000);
        }

        function showError(message) {
            document.getElementById('checking').classList.remove('active');
            document.getElementById('checking').classList.add('hidden');
            document.getElementById('error').classList.remove('hidden');
            document.getElementById('error').classList.add('active');
            document.getElementById('error-details').classList.remove('hidden');
            document.getElementById('error-message').textContent = message;
        }

        function retryVerification() {
            if (verificationAttempts >= maxAttempts) {
                alert('Maximum verification attempts reached. Please check your Tailscale connection and refresh the page.');
                return;
            }
            
            // Reset UI
            document.getElementById('error').classList.add('hidden');
            document.getElementById('error').classList.remove('active');
            document.getElementById('error-details').classList.add('hidden');
            document.getElementById('checking').classList.remove('hidden');
            document.getElementById('checking').classList.add('active');
            
            // Retry verification
            setTimeout(verifyTailscaleConnectivity, 1000);
        }

        // Start verification when page loads
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(verifyTailscaleConnectivity, 1000);
        });
    </script>
</body>
</html>`, 
		customCSS,
		t.config.TestDomain,
		t.config.TestDomain,
		t.config.SuccessMessage,
		t.config.TestDomain,
		originalURL,
		customScript,
	)
}

func (t *TailscaleConnectivityAuth) getDefaultCSS() string {
	return `
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            max-width: 500px;
            width: 100%;
        }

        .verification-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            text-align: center;
            animation: slideUp 0.6s ease-out;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header h1 {
            color: #333;
            margin: 20px 0 10px;
            font-size: 28px;
            font-weight: 600;
        }

        .header p {
            color: #666;
            font-size: 16px;
            margin-bottom: 30px;
        }

        .tailscale-logo {
            display: inline-block;
            margin-bottom: 10px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        .status-container {
            margin: 30px 0;
        }

        .status-item {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            border-radius: 12px;
            margin: 15px 0;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .status-item.active {
            background: #f0f9ff;
            border: 2px solid #3b82f6;
            color: #1e40af;
        }

        .status-item.success {
            background: #ecfdf5;
            border: 2px solid #10b981;
            color: #047857;
        }

        .status-item.error {
            background: #fef2f2;
            border: 2px solid #ef4444;
            color: #dc2626;
        }

        .hidden {
            display: none !important;
        }

        .spinner {
            width: 20px;
            height: 20px;
            border: 2px solid #3b82f6;
            border-top: 2px solid transparent;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 12px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .check-icon, .error-icon {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 12px;
            font-weight: bold;
            font-size: 16px;
        }

        .check-icon {
            background: #10b981;
            color: white;
        }

        .error-icon {
            background: #ef4444;
            color: white;
        }

        .error-details, .success-details {
            text-align: left;
            background: #f9fafb;
            border-radius: 12px;
            padding: 25px;
            margin-top: 20px;
        }

        .error-details h3 {
            color: #374151;
            margin-bottom: 15px;
            font-size: 18px;
        }

        .error-details ol {
            margin: 15px 0;
            padding-left: 20px;
        }

        .error-details li {
            margin: 8px 0;
            color: #4b5563;
            line-height: 1.5;
        }

        .technical-details {
            margin-top: 20px;
            border-top: 1px solid #e5e7eb;
            padding-top: 20px;
        }

        .technical-details summary {
            cursor: pointer;
            font-weight: 500;
            color: #374151;
            padding: 5px 0;
        }

        .technical-details p {
            margin: 10px 0;
            color: #6b7280;
            font-size: 14px;
            line-height: 1.5;
        }

        code {
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
            color: #374151;
        }

        .retry-button {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 20px auto 0;
            transition: background 0.2s;
        }

        .retry-button:hover {
            background: #2563eb;
        }

        .retry-icon {
            margin-right: 8px;
            font-size: 16px;
        }

        .progress-bar {
            width: 100%;
            height: 6px;
            background: #e5e7eb;
            border-radius: 3px;
            overflow: hidden;
            margin: 20px 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #10b981, #34d399);
            animation: progress 3s linear;
        }

        @keyframes progress {
            from { width: 0%; }
            to { width: 100%; }
        }

        .redirect-text {
            color: #6b7280;
            font-size: 14px;
            margin-top: 10px;
        }

        a {
            color: #3b82f6;
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }

        @media (max-width: 480px) {
            .verification-card {
                padding: 30px 20px;
            }
            
            .header h1 {
                font-size: 24px;
            }
            
            .status-item {
                padding: 15px;
                font-size: 14px;
            }
        }
    `
}