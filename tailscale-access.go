// tailscale-access.go
package tailscale_access

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config struct definition
type Config struct {
	TestDomain         string `json:"testDomain,omitempty"`
	SessionTimeout     string `json:"sessionTimeout,omitempty"`
	CustomErrorMessage string `json:"customErrorMessage,omitempty"`
	SuccessMessage     string `json:"successMessage,omitempty"`
	EnableDebugLogging bool   `json:"enableDebugLogging,omitempty"`
	AllowLocalhost     bool   `json:"allowLocalhost,omitempty"`
	CustomCSS          string `json:"customCSS,omitempty"`
	CustomScript       string `json:"customScript,omitempty"`
	SecureOnly         bool   `json:"secureOnly,omitempty"`
	CookieDomain       string `json:"cookieDomain,omitempty"`
	RequireUserAgent   bool   `json:"requireUserAgent,omitempty"`
}

// CreateConfig function
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

// Cookie Status constants
const (
	NO_COOKIE = iota
	INVALID_FORMAT_COOKIE
	EXPIRED_COOKIE
	STALE_COOKIE
	FRESH_COOKIE
)

type CookieStatusResult struct {
	Status    int
	Timestamp int64 // milliseconds, if parsable
	Token     string // if parsable
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.TestDomain == "" {
		return nil, fmt.Errorf("testDomain must be configured")
	}

	var sessionTimeout time.Duration
	var err error

	if config.SessionTimeout != "" {
		sessionTimeout, err = time.ParseDuration(config.SessionTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid sessionTimeout format: %v", err)
		}
	} else {
		sessionTimeout = 24 * time.Hour // Default
	}
	if sessionTimeout <= 0 { // Ensure positive duration
		sessionTimeout = 24 * time.Hour
		if config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Warning: sessionTimeout was invalid or zero, reset to 24h\n")
		}
	}

	if config.CustomErrorMessage == "" {
		config.CustomErrorMessage = "Tailscale connection required to access this service."
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

func (t *TailscaleConnectivityAuth) getCookieStatus(req *http.Request) CookieStatusResult {
	cookie, err := req.Cookie("tailscale_verified")
	if err != nil {
		return CookieStatusResult{Status: NO_COOKIE}
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return CookieStatusResult{Status: INVALID_FORMAT_COOKIE}
	}

	timestampMs, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return CookieStatusResult{Status: INVALID_FORMAT_COOKIE}
	}

	token := parts[1]
	if len(token) < 10 { // Basic sanity check for the token part
		return CookieStatusResult{Status: INVALID_FORMAT_COOKIE}
	}

	currentTimeMs := time.Now().UnixNano() / int64(time.Millisecond)
	cookieAgeMs := currentTimeMs - timestampMs

	if cookieAgeMs < 0 {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Cookie has future timestamp (age: %d ms), invalid.\n", cookieAgeMs)
		}
		return CookieStatusResult{Status: INVALID_FORMAT_COOKIE}
	}

	sessionTimeoutMs := t.sessionTimeout.Milliseconds()
	if sessionTimeoutMs <= 0 { // Should be caught by New()
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Critical Error: sessionTimeoutMs is zero or negative in getCookieStatus.\n")
		}
		return CookieStatusResult{Status: EXPIRED_COOKIE} // Treat as immediately expired
	}

	if cookieAgeMs >= sessionTimeoutMs {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Cookie EXPIRED: age %d ms, sessionTimeout %d ms\n", cookieAgeMs, sessionTimeoutMs)
		}
		return CookieStatusResult{Status: EXPIRED_COOKIE, Timestamp: timestampMs, Token: token}
	}

	// Stale if cookieAgeMs is in the last 20% of its lifetime.
	staleAgeThresholdMs := sessionTimeoutMs * 80 / 100
	if cookieAgeMs >= staleAgeThresholdMs {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Cookie STALE: age %d ms, stale_threshold %d ms, sessionTimeout %d ms\n", cookieAgeMs, staleAgeThresholdMs, sessionTimeoutMs)
		}
		return CookieStatusResult{Status: STALE_COOKIE, Timestamp: timestampMs, Token: token}
	}

	if t.config.EnableDebugLogging {
		fmt.Printf("[TailscaleAuth] Cookie FRESH: age %d ms, sessionTimeout %d ms\n", cookieAgeMs, sessionTimeoutMs)
	}
	return CookieStatusResult{Status: FRESH_COOKIE, Timestamp: timestampMs, Token: token}
}

func (t *TailscaleConnectivityAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if t.config.EnableDebugLogging {
		fmt.Printf("[TailscaleAuth] Request: %s %s from %s, Host: %s\n", req.Method, req.URL.String(), req.RemoteAddr, req.Host)
	}

	if t.config.AllowLocalhost && t.isLocalhost(req) {
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Allowing localhost bypass for %s\n", req.Host)
		}
		t.next.ServeHTTP(rw, req)
		return
	}

	if t.config.RequireUserAgent {
		if req.Header.Get("User-Agent") == "" {
			if t.config.EnableDebugLogging {
				fmt.Printf("[TailscaleAuth] Missing User-Agent for %s, showing verification page\n", req.URL.String())
			}
			t.serveVerificationPage(rw, req) // Treat as unverified
			return
		}
	}

	cookieCheckResult := t.getCookieStatus(req)

	switch cookieCheckResult.Status {
	case FRESH_COOKIE:
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] FRESH_COOKIE for %s, allowing access.\n", req.URL.String())
		}
		t.next.ServeHTTP(rw, req)
		return
	case STALE_COOKIE:
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] STALE_COOKIE for %s %s.\n", req.Method, req.URL.String())
		}
		if req.Method == http.MethodGet {
			if t.config.EnableDebugLogging {
				fmt.Printf("[TailscaleAuth] Attempting silent refresh for GET request.\n")
			}
			t.serveSilentRefreshPage(rw, req, req.URL.String()) // Pass originalURL for redirection
		} else {
			if t.config.EnableDebugLogging {
				fmt.Printf("[TailscaleAuth] Stale cookie on non-GET request (%s), allowing to avoid disruption.\n", req.Method)
			}
			t.next.ServeHTTP(rw, req) // Allow current non-GET, next GET will refresh
		}
		return
	case NO_COOKIE, INVALID_FORMAT_COOKIE, EXPIRED_COOKIE:
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Cookie status %d for %s, showing full verification page.\n", cookieCheckResult.Status, req.URL.String())
		}
		t.serveVerificationPage(rw, req)
		return
	default:
		if t.config.EnableDebugLogging {
			fmt.Printf("[TailscaleAuth] Unknown cookie status %d for %s, showing full verification page as fallback.\n", cookieCheckResult.Status, req.URL.String())
		}
		t.serveVerificationPage(rw, req)
		return
	}
}

func (t *TailscaleConnectivityAuth) isLocalhost(req *http.Request) bool {
	host := req.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func (t *TailscaleConnectivityAuth) serveVerificationPage(rw http.ResponseWriter, req *http.Request) {
	originalURL := req.URL.String()

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	rw.Header().Set("Expires", "0")
	rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(http.StatusOK)

	html := t.generateVerificationHTML(originalURL)
	_, _ = rw.Write([]byte(html))
}

func (t *TailscaleConnectivityAuth) serveSilentRefreshPage(rw http.ResponseWriter, req *http.Request, originalURL string) {
	sessionTimeoutMilliseconds := t.sessionTimeout.Milliseconds()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verifying Session...</title>
    <script>
        const testDomain = '%s';
        const originalURL = '%s';
        const sessionTimeoutMilliseconds = %d;
        const cookieDomain = '%s'; // String, empty if not set
        const secureFlag = %t;   // Boolean true/false

        async function silentVerifyAndRefresh() {
            if (typeof console !== 'undefined' && console.log) {
                console.log('TailscaleAuth: Performing silent verification for original URL:', originalURL);
            }
            let verified = false;
            try {
                let connectivityTestUrl = testDomain;
                if (!connectivityTestUrl.startsWith('http://') && !connectivityTestUrl.startsWith('https://')) {
                    connectivityTestUrl = (window.location.protocol === 'https:' ? 'https://' : 'http://') + testDomain;
                }
                connectivityTestUrl += (connectivityTestUrl.includes('?') ? '&' : '?') + 'ts_refresh_v3=' + Date.now();

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

                try {
                    await fetch(connectivityTestUrl, {
                        method: 'GET', mode: 'no-cors', cache: 'no-cache', credentials: 'omit', signal: controller.signal
                    });
                    clearTimeout(timeoutId);
                    verified = true;
                    if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Silent fetch verification successful.');
                } catch (fetchError) {
                    clearTimeout(timeoutId);
                    if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Silent fetch failed:', fetchError.message, '. Trying image fallback.');
                    
                    try {
                        await new Promise((resolve, reject) => {
                            const img = new Image();
                            const imgTimeout = setTimeout(() => {
                                img.onerror = null; img.onload = null;
                                reject(new Error('TailscaleAuth: Silent image load timeout'));
                            }, 4000); // 4s for image
                            img.onload = () => { clearTimeout(imgTimeout); resolve(); };
                            img.onerror = (errEvent) => { clearTimeout(imgTimeout); reject(new Error('TailscaleAuth: Silent image load failed - ' + (errEvent ? errEvent.type : 'unknown error'))); };
                            
                            let imgBaseUrl = testDomain;
                            if (!imgBaseUrl.startsWith('http://') && !imgBaseUrl.startsWith('https://')) {
                                imgBaseUrl = (window.location.protocol === 'https:' ? 'https://' : 'http://') + testDomain;
                            }
                            const urlObj = new URL(imgBaseUrl);
                            img.src = urlObj.protocol + '//' + urlObj.host + '/favicon.ico?ts_refresh_img_v3=' + Date.now();
                        });
                        verified = true;
                        if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Silent image verification successful.');
                    } catch (imgError) {
                        if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Silent image verification failed:', imgError.message);
                    }
                }
            } catch (e) {
                if (typeof console !== 'undefined' && console.error) console.error('TailscaleAuth: Error during silent verification:', e);
            }

            if (verified) {
                const newTimestamp = Date.now();
                const newTokenPart = Array(16).fill(0).map(() => Math.floor(Math.random() * 36).toString(36)).join('');
                const cookieValue = newTimestamp + "." + newTokenPart;
                
                const expiry = new Date();
                expiry.setTime(newTimestamp + sessionTimeoutMilliseconds);
                
                let cookieString = 'tailscale_verified=' + cookieValue +
                                   '; expires=' + expiry.toUTCString() +
                                   '; path=/;';
                if (cookieDomain) { cookieString += ' domain=' + cookieDomain + ';'; }
                if (secureFlag) { cookieString += ' secure;'; }
                cookieString += ' samesite=lax';
                document.cookie = cookieString;
                if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Cookie refreshed. Redirecting to:', originalURL);
            } else {
                if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Silent verification failed. Clearing cookie.');
                let expiryPast = new Date(0).toUTCString();
                let clearCookieString = 'tailscale_verified=; expires=' + expiryPast + '; path=/;';
                if (cookieDomain) { clearCookieString += ' domain=' + cookieDomain + ';'; }
                document.cookie = clearCookieString;
                if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Cookie cleared. Redirecting to original URL:', originalURL);
            }
            window.location.href = originalURL; // Always redirect
        }
        
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', silentVerifyAndRefresh);
        } else {
            silentVerifyAndRefresh();
        }
    </script>
</head>
<body><p>Verifying session...</p></body>
</html>`,
		t.config.TestDomain,
		originalURL,
		sessionTimeoutMilliseconds,
		t.config.CookieDomain,
		t.config.SecureOnly,
	)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	rw.Header().Set("Expires", "0")
	rw.Header().Set("Pragma", "no-cache")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte(html))
}

func (t *TailscaleConnectivityAuth) generateVerificationHTML(originalURL string) string {
	customCSS := t.config.CustomCSS
	if customCSS == "" {
		customCSS = t.getDefaultCSS() // This will use the updated CSS
	}
	customScript := t.config.CustomScript
	sessionTimeoutMilliseconds := t.sessionTimeout.Milliseconds()

	secureCookieFlagString := ""
	if t.config.SecureOnly {
		secureCookieFlagString = "secure;"
	}
	cookieDomainDirective := ""
	if t.config.CookieDomain != "" {
		cookieDomainDirective = fmt.Sprintf("domain=%s;", t.config.CookieDomain)
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
                <div class="tailscale-logo"><svg width="40" height="40" viewBox="0 0 100 100" fill="none"><circle cx="50" cy="50" r="45" fill="#000"/><path d="M25 35h50v30H25z" fill="#fff"/><circle cx="35" cy="50" r="5" fill="#000"/><circle cx="65" cy="50" r="5" fill="#000"/></svg></div>
                <h1>Tailscale Verification</h1>
                <p>Verifying your Tailscale connection...</p>
            </div>
            <div class="status-container">
                <div id="checking" class="status-item active"><div class="spinner"></div><span>Testing Tailscale connectivity...</span></div>
                <div id="success" class="status-item success hidden"><div class="check-icon">✓</div><span>Tailscale connection verified!</span></div>
                <div id="error" class="status-item error hidden"><div class="error-icon">✗</div><span>Tailscale connection not detected</span></div>
            </div>
            <div id="error-details" class="error-details hidden">
                <h3>How to connect via Tailscale:</h3>
                <ol>
                    <li><strong>Install Tailscale</strong> from <a href="https://tailscale.com/download" target="_blank">tailscale.com/download</a></li>
                    <li><strong>Connect to your network</strong> and ensure you can access <code>%s</code></li>
                    <li><strong>Refresh this page</strong> to try again</li>
                </ol>
                <div class="technical-details">
                    <details><summary>Technical Details</summary>
                        <p>This service requires access through a Tailscale network. We test connectivity by attempting to reach your Tailscale domain.</p>
                        <p><strong>Test Domain:</strong> <code>%s</code></p>
                        <p><strong>Error:</strong> <span id="error-message">Connection failed</span></p>
                    </details>
                </div>
                <button onclick="retryVerification()" class="retry-button"><span class="retry-icon">↻</span> Try Again</button>
            </div>
            <div id="success-details" class="success-details hidden">
                <p>%s</p>
                <div class="progress-bar"><div class="progress-fill"></div></div>
                <p class="redirect-text">Redirecting in <span id="countdown">3</span> seconds...</p>
            </div>
        </div>
    </div>
    <script>
        let verificationAttempts = 0;
        const maxAttempts = 3;
        const testDomain = '%s';
        const originalURL = '%s';
        const sessionTimeoutMilliseconds = %d;

        %s // Custom Script Placeholder

        async function verifyTailscaleConnectivity() {
            verificationAttempts++;
            const checkingDiv = document.getElementById('checking');
            const errorDiv = document.getElementById('error');
            const errorDetailsDiv = document.getElementById('error-details');

            if(checkingDiv) { checkingDiv.classList.add('active'); checkingDiv.classList.remove('hidden'); }
            if(errorDiv) errorDiv.classList.add('hidden');
            if(errorDetailsDiv) errorDetailsDiv.classList.add('hidden');
            
            if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Verification attempt', verificationAttempts, 'for domain:', testDomain);
            
            let verified = false;
            let lastErrorMessage = 'Connectivity tests failed.';
            try {
                let connectivityTestUrl = testDomain;
                if (!connectivityTestUrl.startsWith('http://') && !connectivityTestUrl.startsWith('https://')) {
                    connectivityTestUrl = (window.location.protocol === 'https:' ? 'https://' : 'http://') + testDomain;
                }
                connectivityTestUrl += (connectivityTestUrl.includes('?') ? '&' : '?') + 'ts_main_check_v3=' + Date.now();

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 8000); 

                try {
                    await fetch(connectivityTestUrl, { method: 'GET', mode: 'no-cors', cache: 'no-cache', credentials: 'omit', signal: controller.signal });
                    clearTimeout(timeoutId);
                    verified = true;
                } catch (fetchError) {
                    clearTimeout(timeoutId);
                    lastErrorMessage = 'Fetch failed: ' + fetchError.message;
                    if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Fetch failed, trying image. Error:', fetchError.message);
                    try {
                         await new Promise((resolve, reject) => {
                            const img = new Image();
                            const imgTimeout = setTimeout(() => { img.onerror = null; img.onload = null; reject(new Error('TailscaleAuth: Image load timeout')); }, 5000);
                            img.onload = () => { clearTimeout(imgTimeout); resolve(); };
                            img.onerror = (errEvent) => { clearTimeout(imgTimeout); reject(new Error('TailscaleAuth: Image load failed - ' + (errEvent ? errEvent.type : 'unknown error'))); };
                            
                            let imgBaseUrl = testDomain;
                            if (!imgBaseUrl.startsWith('http://') && !imgBaseUrl.startsWith('https://')) {
                                imgBaseUrl = (window.location.protocol === 'https:' ? 'https://' : 'http://') + testDomain;
                            }
                            const urlObj = new URL(imgBaseUrl);
                            img.src = urlObj.protocol + '//' + urlObj.host + '/favicon.ico?ts_main_img_v3=' + Date.now();
                        });
                        verified = true;
                        lastErrorMessage = ''; 
                    } catch (imgError) {
                         lastErrorMessage += '. Image fallback failed: ' + imgError.message;
                         if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Image fallback failed:', imgError.message);
                    }
                }
            } catch (e) {
                 lastErrorMessage = 'Unexpected error: ' + e.message;
                 if (typeof console !== 'undefined' && console.error) console.error('TailscaleAuth: Error during main verification:', e);
            }

            if(verified) {
                setVerificationCookieAndRedirect();
            } else {
                showError(lastErrorMessage);
            }
        }

        function setVerificationCookieAndRedirect() {
            if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Setting verification cookie.');
            
            const newTimestamp = Date.now();
            const clientSideTokenPart = Array(16).fill(0).map(() => Math.floor(Math.random() * 36).toString(36)).join('');
            const cookieValueToSet = newTimestamp + "." + clientSideTokenPart;
            
            const expiry = new Date();
            expiry.setTime(newTimestamp + sessionTimeoutMilliseconds);
            
            let cookieString = 'tailscale_verified=' + cookieValueToSet + 
                               '; expires=' + expiry.toUTCString() + 
                               '; path=/;' +
                               '%s' + // cookieDomainDirective
                               '%s' + // secureCookieFlagString
                               ' samesite=lax';
            document.cookie = cookieString;
            if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Verification cookie set. Value:', cookieValueToSet.substring(0, cookieValueToSet.indexOf('.') + 4) + '...');
            
            showSuccess();
            setTimeout(() => {
                if (typeof console !== 'undefined' && console.log) console.log('TailscaleAuth: Redirecting to original URL:', originalURL);
                window.location.href = originalURL;
            }, 3000);
        }

        function showSuccess() {
            const checkingDiv = document.getElementById('checking');
            const successDiv = document.getElementById('success');
            const successDetailsDiv = document.getElementById('success-details');
            if(checkingDiv) { checkingDiv.classList.remove('active'); checkingDiv.classList.add('hidden'); }
            if(successDiv) { successDiv.classList.remove('hidden'); successDiv.classList.add('active'); }
            if(successDetailsDiv) successDetailsDiv.classList.remove('hidden');
            
            let countdown = 3;
            const countdownElement = document.getElementById('countdown');
            if(countdownElement) countdownElement.textContent = countdown;
            const countdownTimer = setInterval(() => {
                countdown--;
                if(countdownElement) countdownElement.textContent = countdown;
                if (countdown <= 0) clearInterval(countdownTimer);
            }, 1000);
        }

        function showError(message) {
            const checkingDiv = document.getElementById('checking');
            const errorDiv = document.getElementById('error');
            const errorDetailsDiv = document.getElementById('error-details');
            const errorMsgElem = document.getElementById('error-message');

            if(checkingDiv) { checkingDiv.classList.remove('active'); checkingDiv.classList.add('hidden'); }
            if(errorDiv) { errorDiv.classList.remove('hidden'); errorDiv.classList.add('active'); }
            if(errorDetailsDiv) errorDetailsDiv.classList.remove('hidden');
            if(errorMsgElem) errorMsgElem.textContent = message;
        }

        function retryVerification() {
            if (verificationAttempts >= maxAttempts) {
                alert('Maximum verification attempts reached. Please check your Tailscale connection and refresh the page manually.');
                return;
            }
            const errorDiv = document.getElementById('error');
            const errorDetailsDiv = document.getElementById('error-details');
            const successDiv = document.getElementById('success');
            const successDetailsDiv = document.getElementById('success-details');

            if(errorDiv) errorDiv.classList.add('hidden');
            if(errorDetailsDiv) errorDetailsDiv.classList.add('hidden');
            if(successDiv) successDiv.classList.add('hidden');
            if(successDetailsDiv) successDetailsDiv.classList.add('hidden');
            
            setTimeout(verifyTailscaleConnectivity, 200);
        }

        if (document.readyState === 'loading') {
             document.addEventListener('DOMContentLoaded', () => setTimeout(verifyTailscaleConnectivity, 200));
        } else {
            setTimeout(verifyTailscaleConnectivity, 200);
        }
    </script>
</body>
</html>`,
		customCSS,
		t.config.TestDomain,
		t.config.TestDomain,
		t.config.SuccessMessage,
		t.config.TestDomain,
		originalURL,
		sessionTimeoutMilliseconds,
		customScript,
		cookieDomainDirective,
		secureCookieFlagString,
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
            background: linear-gradient(120deg, #5E72E4 0%, #825EE4 50%, #4158D0 100%);
            background-size: 250% 250%;
            animation: gradientBG 12s ease infinite;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            overflow: hidden;
        }

        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .container {
            max-width: 500px;
            width: 100%;
        }

        .verification-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.2), 0 0 15px rgba(0,0,0,0.05);
            padding: 40px;
            text-align: center;
            animation: slideUp 0.7s cubic-bezier(0.25, 0.8, 0.25, 1);
            position: relative;
            z-index: 1;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(40px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .header h1 { color: #333; margin: 20px 0 10px; font-size: 28px; font-weight: 600; }
        .header p { color: #666; font-size: 16px; margin-bottom: 30px; }

        .tailscale-logo { display: inline-block; margin-bottom: 10px; animation: pulseLogo 2.5s infinite ease-in-out; }
        @keyframes pulseLogo {
            0%, 100% { transform: scale(1); opacity: 0.85; }
            50% { transform: scale(1.04); opacity: 1; }
        }

        .status-container { margin: 30px 0; }
        .status-item {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 18px 20px;
            border-radius: 12px;
            margin: 15px 0;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.35s cubic-bezier(0.25, 0.8, 0.25, 1);
            border-width: 1px;
            border-style: solid;
        }

        .status-item.active {
            background: #edf2ff;
            border-color: #788ff7;
            color: #3a50a3;
            transform: scale(1.03);
            box-shadow: 0 5px 20px rgba(94, 114, 228, 0.25);
        }
        .status-item.success {
            background: #e6f9f0;
            border-color: #50d38a;
            color: #00702d;
            transform: scale(1.03);
            box-shadow: 0 5px 20px rgba(0, 200, 81, 0.2);
        }
        .status-item.error {
            background: #fff0f0;
            border-color: #ff7777;
            color: #c00000;
            transform: scale(1.03);
            box-shadow: 0 5px 20px rgba(255, 68, 68, 0.2);
        }
        .hidden { display: none !important; }

        .spinner {
            width: 22px;
            height: 22px;
            border-radius: 50%;
            position: relative;
            animation: spinnerRotate 0.9s linear infinite;
            margin-right: 15px;
            border: none;
        }
        .spinner::before {
            content: "";
            position: absolute;
            border-radius: 50%;
            inset: 0;
            border: 3px solid #a1bfff;
            border-top-color: #5E72E4;
        }
        @keyframes spinnerRotate { to { transform: rotate(360deg); } }

        .check-icon, .error-icon {
            width: 24px; height: 24px; border-radius: 50%; display: flex;
            align-items: center; justify-content: center; margin-right: 12px;
            font-weight: bold; font-size: 16px; color: white;
        }
        .check-icon { background: #00C851; }
        .error-icon { background: #FF4444; }

        .error-details, .success-details { text-align: left; background: #f8f9fa; border-radius: 12px; padding: 25px; margin-top: 20px; }
        .error-details h3 { color: #374151; margin-bottom: 15px; font-size: 18px; }
        .error-details ol { margin: 15px 0; padding-left: 20px; }
        .error-details li { margin: 8px 0; color: #4b5563; line-height: 1.5; }
        .technical-details { margin-top: 20px; border-top: 1px solid #e5e7eb; padding-top: 20px; }
        .technical-details summary {
            cursor: pointer; font-weight: 500; color: #55595e;
            padding: 10px 5px; border-radius: 6px; transition: background-color 0.2s, color 0.2s;
        }
        .technical-details summary:hover, .technical-details summary:focus { color: #000; background-color: #e9ecef; }
        .technical-details p { margin: 10px 0; color: #6b7280; font-size: 14px; line-height: 1.5; }

        code { background: #e9ecef; padding: 3px 7px; border-radius: 4px; font-family: 'SF Mono', Monaco, monospace; font-size: 13px; color: #cb0000; }

        .retry-button {
            background: #5E72E4; color: white; border: none; padding: 12px 28px;
            border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer;
            display: inline-flex; align-items: center; justify-content: center;
            margin: 25px auto 0;
            transition: background-color 0.2s, transform 0.15s ease-out, box-shadow 0.2s ease-out;
            box-shadow: 0 3px 6px rgba(0,0,0,0.1);
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .retry-button:hover { background: #4e63d4; box-shadow: 0 6px 12px rgba(94, 114, 228, 0.3); transform: translateY(-2px); }
        .retry-button:active { transform: translateY(0px) scale(0.98); box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .retry-icon { margin-right: 10px; font-size: 16px; }

        .progress-bar { width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; margin: 20px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #00C851, #00E676); animation: progress 3s linear; border-radius: 4px; }
        @keyframes progress { from { width: 0%; } to { width: 100%; } }

        .redirect-text { color: #6b7280; font-size: 14px; margin-top: 10px; }
        a { color: #5E72E4; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; color: #4e63d4; }

        @media (max-width: 480px) {
            .verification-card { padding: 30px 20px; }
            .header h1 { font-size: 24px; }
            .status-item { padding: 15px; font-size: 14px; }
            .retry-button { padding: 10px 20px; font-size: 14px; }
        }
    `
}