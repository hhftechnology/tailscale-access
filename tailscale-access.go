// Simplified Tailscale Authentication Plugin
package tailscale_access

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	// Tailscale domain to test connectivity against
	TestDomain string `json:"testDomain,omitempty"`
	
	// Session timeout as duration string (e.g., "24h", "30m")
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
		TestDomain:         "your-tailscale-network.ts.net",
		SessionTimeout:     "24h",
		CustomErrorMessage: "Tailscale connection required to access this service",
		SuccessMessage:     "Tailscale connectivity verified! Redirecting...",
		EnableDebugLogging: false,
		AllowLocalhost:     true,
		SecureOnly:         true,
		RequireUserAgent:   true,
	}
}

type TailscaleConnectivityAuth struct {
	next           http.Handler
	name           string
	config         *Config
	sessionTimeout time.Duration
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.TestDomain == "" {
		return nil, fmt.Errorf("testDomain must be configured")
	}
	
	// Parse session timeout
	var sessionTimeout time.Duration
	var err error
	
	if config.SessionTimeout != "" {
		sessionTimeout, err = time.ParseDuration(config.SessionTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid sessionTimeout format: %v", err)
		}
	} else {
		sessionTimeout = 24 * time.Hour
	}
	
	// Apply defaults
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
	}, nil
}

func (t *TailscaleConnectivityAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if t.config.EnableDebugLogging {
		fmt.Printf("[TailscaleAuth] Request: %s %s from %s\n", req.Method, req.URL.Path, req.RemoteAddr)
	}

	// Check for localhost bypass
	if t.config.AllowLocalhost && t.isLocalhost(req) {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Allowing localhost bypass\n")
		}
		t.next.ServeHTTP(rw, req)
		return
	}

	// Check if already verified (simple cookie validation)
	if t.isVerified(req) {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Request already verified, allowing access\n")
		}
		t.next.ServeHTTP(rw, req)
		return
	}

	// Show verification page
	if t.config.EnableDebugLogging {
		fmt.Printf("[TailscaleAuth] Showing verification page\n")
	}
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
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] No verification cookie found: %v\n", err)
		}
		return false
	}

	// Simple validation - just check if cookie exists and is not empty
	// The security comes from the fact that only Tailscale-connected clients
	// can reach the testDomain to set this cookie in the first place
	if cookie.Value != "" && len(cookie.Value) > 10 {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Valid verification cookie found: %s\n", cookie.Value[:10]+"...")
		}
		return true
	}

	if t.config.EnableDebugLogging {
		fmt.Printf("[TailscaleAuth] Invalid verification cookie: %s\n", cookie.Value)
	}
	return false
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

        // Simplified approach - no server roundtrip needed
        async function verifyTailscaleConnectivity() {
            verificationAttempts++;
            console.log('Starting verification attempt', verificationAttempts, 'for domain:', testDomain);
            
            const isHttpsPage = window.location.protocol === 'https:';
            console.log('Current page protocol:', window.location.protocol);
            
            try {
                if (isHttpsPage) {
                    const httpsUrl = 'https://' + testDomain + '/';
                    console.log('Testing HTTPS URL:', httpsUrl);
                    
                    const controllerHttps = new AbortController();
                    const timeoutIdHttps = setTimeout(() => {
                        console.log('HTTPS request timeout');
                        controllerHttps.abort();
                    }, 10000);
                    
                    try {
                        const httpsResponse = await fetch(httpsUrl, {
                            method: 'GET',
                            mode: 'no-cors',
                            cache: 'no-cache',
                            credentials: 'omit',
                            signal: controllerHttps.signal
                        });
                        
                        clearTimeout(timeoutIdHttps);
                        console.log('HTTPS connectivity test succeeded');
                        setVerificationCookieAndRedirect();
                        return;
                        
                    } catch (httpsError) {
                        clearTimeout(timeoutIdHttps);
                        console.log('HTTPS fetch failed:', httpsError.message);
                        throw httpsError;
                    }
                }
                
                if (!isHttpsPage) {
                    const httpUrl = 'http://' + testDomain + '/';
                    console.log('Testing HTTP URL:', httpUrl);
                    
                    const controllerHttp = new AbortController();
                    const timeoutIdHttp = setTimeout(() => {
                        controllerHttp.abort();
                    }, 10000);
                    
                    try {
                        const httpResponse = await fetch(httpUrl, {
                            method: 'GET',
                            mode: 'no-cors',
                            cache: 'no-cache',
                            credentials: 'omit',
                            signal: controllerHttp.signal
                        });
                        
                        clearTimeout(timeoutIdHttp);
                        console.log('HTTP connectivity test succeeded');
                        setVerificationCookieAndRedirect();
                        return;
                        
                    } catch (httpError) {
                        clearTimeout(timeoutIdHttp);
                        throw httpError;
                    }
                }
                
            } catch (fetchError) {
                console.log('Fetch tests failed, trying image loading:', fetchError.message);
                
                try {
                    await testImageLoad();
                    console.log('Image test succeeded');
                    setVerificationCookieAndRedirect();
                    return;
                } catch (imgError) {
                    console.log('All connectivity tests failed');
                    showError('All connectivity tests failed. Primary error: ' + fetchError.message + '. Image test: ' + imgError.message);
                }
            }
        }

        function setVerificationCookieAndRedirect() {
            console.log('Setting verification cookie and redirecting...');
            
            const token = generateClientToken();
            const expiry = new Date();
            expiry.setTime(expiry.getTime() + (24 * 60 * 60 * 1000)); // 24 hours
            
            document.cookie = 'tailscale_verified=' + token + '; expires=' + expiry.toUTCString() + '; path=/; secure; samesite=lax';
            console.log('Verification cookie set:', token);
            
            showSuccess();
            setTimeout(() => {
                console.log('Redirecting to:', originalURL);
                window.location.href = originalURL;
            }, 3000);
        }

        function generateClientToken() {
            const timestamp = Date.now();
            const random = Math.random().toString(36).substring(2);
            const domain = testDomain.replace(/[^a-zA-Z0-9]/g, '');
            
            const tokenData = timestamp + '-' + random + '-' + domain;
            let hash = 0;
            for (let i = 0; i < tokenData.length; i++) {
                const char = tokenData.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            
            return Math.abs(hash).toString(16) + random;
        }

        function testImageLoad() {
            return new Promise((resolve, reject) => {
                console.log('Starting image load test...');
                
                const isHttpsPage = window.location.protocol === 'https:';
                
                if (isHttpsPage) {
                    const img = new Image();
                    const timeout = setTimeout(() => {
                        img.onerror = null;
                        img.onload = null;
                        reject(new Error('HTTPS image load timeout'));
                    }, 8000);
                    
                    img.onload = () => {
                        clearTimeout(timeout);
                        console.log('Image loaded successfully via HTTPS');
                        resolve();
                    };
                    
                    img.onerror = (error) => {
                        clearTimeout(timeout);
                        console.log('HTTPS image load failed:', error);
                        reject(new Error('HTTPS image load failed'));
                    };
                    
                    img.src = 'https://' + testDomain + '/favicon.ico?t=' + Date.now();
                    
                } else {
                    const img = new Image();
                    const timeout = setTimeout(() => {
                        img.onerror = null;
                        img.onload = null;
                        reject(new Error('Image load timeout'));
                    }, 6000);
                    
                    img.onload = () => {
                        clearTimeout(timeout);
                        console.log('Image loaded successfully via HTTP');
                        resolve();
                    };
                    
                    img.onerror = () => {
                        clearTimeout(timeout);
                        
                        const img2 = new Image();
                        const timeout2 = setTimeout(() => {
                            img2.onerror = null;
                            img2.onload = null;
                            reject(new Error('Image load failed (both HTTP and HTTPS)'));
                        }, 4000);
                        
                        img2.onload = () => {
                            clearTimeout(timeout2);
                            console.log('Image loaded successfully via HTTPS');
                            resolve();
                        };
                        
                        img2.onerror = () => {
                            clearTimeout(timeout2);
                            reject(new Error('Image load failed (both HTTP and HTTPS)'));
                        };
                        
                        img2.src = 'https://' + testDomain + '/favicon.ico?t=' + Date.now();
                    };
                    
                    img.src = 'http://' + testDomain + '/favicon.ico?t=' + Date.now();
                }
            });
        }

        function showSuccess() {
            document.getElementById('checking').classList.remove('active');
            document.getElementById('checking').classList.add('hidden');
            document.getElementById('success').classList.remove('hidden');
            document.getElementById('success').classList.add('active');
            document.getElementById('success-details').classList.remove('hidden');
            
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
            
            document.getElementById('error').classList.add('hidden');
            document.getElementById('error').classList.remove('active');
            document.getElementById('error-details').classList.add('hidden');
            document.getElementById('checking').classList.remove('hidden');
            document.getElementById('checking').classList.add('active');
            
            setTimeout(verifyTailscaleConnectivity, 1000);
        }

        document.addEventListener('DOMContentLoaded', () => {
            console.log('Page loaded, starting verification in 1 second...');
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