# Tailscale Connectivity Authentication Plugin for Traefik

A revolutionary Traefik middleware plugin that provides secure access control by **actually testing Tailscale connectivity** rather than relying on unreliable IP address checking. This plugin solves the complex challenge of verifying real Tailscale connections in modern networking environments.

##  Why This Approach is Superior

### The Problem with IP-Based Authentication

Traditional approaches (including our previous version) try to identify Tailscale clients by checking IP ranges like `100.64.0.0/10`. This fails spectacularly in real-world scenarios:

- **Proxy Hell**: Multiple layers of reverse proxies (nginx, Gerbil, Cloudflare, etc.) mangle or hide the original client IP
- **Container Networking**: Docker networks, Kubernetes service meshes, and container networking completely obscure the real client IP
- **NAT and Firewalls**: Corporate firewalls and NAT devices change source IPs unpredictably
- **Cloud Load Balancers**: AWS ALB, Google Cloud Load Balancer, etc., replace client IPs with their own
- **Header Spoofing**: HTTP headers like `X-Forwarded-For` can be easily spoofed by malicious clients

### Our Connectivity-Based Solution

Instead of guessing IP addresses, we **actually test if the client can reach your Tailscale network**:

✅ **Real Connectivity Test**: JavaScript-based verification that actually tries to connect to your `.ts.net` domain  
✅ **Proxy-Agnostic**: Works regardless of how many proxies are between client and server  
✅ **Container-Friendly**: No dependency on IP address visibility  
✅ **User-Friendly**: Clear verification flow with helpful error messages  
✅ **Secure Sessions**: Cryptographically secure session tokens after verification  
✅ **Beautiful UI**: Modern, responsive verification interface  

##  How It Works

1. **Interception**: Plugin intercepts requests to protected resources
2. **Session Check**: Looks for existing valid verification session
3. **Verification Page**: If not verified, serves an interactive verification page
4. **Connectivity Test**: JavaScript tests actual connectivity to your `.ts.net` domain using multiple methods:
   - Direct HTTPS fetch to your Tailscale domain
   - Image loading test as fallback
   - WebSocket connectivity test as secondary fallback
5. **Session Creation**: On successful verification, creates secure session cookie
6. **Access Granted**: Subsequent requests with valid session are allowed through

##  What Users See

When accessing a protected resource without verification, users see a beautiful verification page that:

- Tests connectivity to your Tailscale domain in real-time
- Shows a progress indicator during verification
- Provides clear success feedback with automatic redirect
- Offers helpful troubleshooting information on failure
- Includes direct links to Tailscale installation and setup guides

## 🛠 Installation & Configuration

### Step 1: Add Plugin to Traefik

```yaml
# traefik.yml
experimental:
  plugins:
    tailscale-connectivity:
      moduleName: github.com/hhftechnology/tailscale-access
      version: v2.0.0
```

### Step 2: Configure Middleware

```yaml
# dynamic-config.yml
http:
  middlewares:
    tailscale-auth:
      plugin:
        tailscale-connectivity:
          testDomain: "your-company.ts.net"  # REQUIRED: Your Tailscale domain
          sessionTimeout: "24h"              # How long verification lasts
          allowLocalhost: true               # Allow localhost for development
```

### Step 3: Apply to Routes

```yaml
http:
  routers:
    protected-service:
      rule: "Host(`internal.company.com`)"
      service: "my-backend-service"
      middlewares:
        - "tailscale-auth"
```

##  Configuration Options

### Basic Configuration

```yaml
tailscale-connectivity:
  testDomain: "mycompany.ts.net"    # REQUIRED: Your Tailscale domain to test against
  sessionTimeout: "24h"             # Session validity duration (default: 24h)
  allowLocalhost: true              # Allow localhost bypass for development (default: true)
  enableDebugLogging: false         # Enable debug logging (default: false)
```

### Production Configuration

```yaml
tailscale-connectivity:
  testDomain: "production.ts.net"
  sessionTimeout: "8h"              # Shorter sessions for production
  allowLocalhost: false             # No localhost bypass in production
  secureOnly: true                  # Require HTTPS for cookies (default: true)
  cookieDomain: ".company.com"      # Restrict cookie scope
  customErrorMessage: "Company VPN connection required"
  successMessage: "VPN verified! Redirecting to dashboard..."
```

### Custom Styling

```yaml
tailscale-connectivity:
  testDomain: "company.ts.net"
  customCSS: |
    /* Company branding */
    body {
      background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%);
    }
    .verification-card {
      border-top: 5px solid #f59e0b;
    }
    .header h1 {
      color: #1e3a8a;
    }
```

##  Use Cases

### Corporate Internal Tools

Protect company dashboards, admin panels, and internal APIs:

```yaml
internal-tools-auth:
  plugin:
    tailscale-connectivity:
      testDomain: "corp.ts.net"
      sessionTimeout: "8h"
      customErrorMessage: "Internal tools require corporate VPN access"
```

### Development Environments

Allow both Tailscale and localhost access for development:

```yaml
dev-auth:
  plugin:
    tailscale-connectivity:
      testDomain: "dev.ts.net"
      sessionTimeout: "168h"    # 1 week for convenience
      allowLocalhost: true
      enableDebugLogging: true
```

### Multi-Tenant Access

Different Tailscale networks for different user groups:

```yaml
# Customer portal
customer-auth:
  plugin:
    tailscale-connectivity:
      testDomain: "customers.ts.net"
      sessionTimeout: "4h"

# Partner API
partner-auth:
  plugin:
    tailscale-connectivity:
      testDomain: "partners.ts.net"
      sessionTimeout: "2h"
```

##  Docker Compose Example

```yaml
version: '3.8'
services:
  traefik:
    image: traefik:v3.0
    command:
      - "--experimental.plugins.tailscale-connectivity.modulename=github.com/hhftechnology/tailscale-access"
      - "--experimental.plugins.tailscale-connectivity.version=v2.0.0"
    volumes:
      - ./config:/etc/traefik/dynamic
    ports:
      - "80:80"
      - "443:443"

  my-app:
    image: nginx:alpine
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-app.rule=Host(`app.company.com`)"
      - "traefik.http.routers.my-app.middlewares=tailscale-auth"
```

##  Kubernetes Example

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: tailscale-auth
spec:
  plugin:
    tailscale-connectivity:
      testDomain: "k8s.ts.net"
      sessionTimeout: "12h"
      customErrorMessage: "Kubernetes access requires Tailscale"

---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: protected-ingress
spec:
  routes:
    - match: Host(`dashboard.k8s.company.com`)
      kind: Rule
      middlewares:
        - name: tailscale-auth
      services:
        - name: kubernetes-dashboard
          port: 443
```

##  Troubleshooting

### Enable Debug Mode

```yaml
tailscale-connectivity:
  enableDebugLogging: true
```

### Common Issues

**❌ "testDomain must be configured"**  
- You must specify your Tailscale domain in the configuration

** Verification always fails**  
- Ensure your Tailscale domain is accessible from client browsers
- Check that the domain responds to HTTPS requests
- Verify Tailscale is running on client devices

** Sessions expire too quickly**  
- Increase `sessionTimeout` value
- Check that cookies are being set properly (requires HTTPS in production)

### Testing Your Setup

1. **Verify your Tailscale domain is accessible:**
   ```bash
   # From a Tailscale-connected device:
   curl -I https://your-domain.ts.net/
   ```

2. **Test the verification flow:**
   - Access your protected service from a non-Tailscale device
   - Should see the verification page
   - Connect to Tailscale and refresh
   - Should automatically verify and redirect

##  Security Features

- **Cryptographically Secure Tokens**: Session tokens use SHA-256 hashing
- **HttpOnly Cookies**: Session cookies are not accessible via JavaScript
- **Secure Cookie Options**: HTTPS-only cookies in production mode
- **Session Timeout**: Configurable automatic session expiration
- **Domain Restriction**: Optional cookie domain scoping
- **No IP Dependencies**: Not vulnerable to IP spoofing attacks

## 🎨 Customization

### Custom Error Messages

```yaml
customErrorMessage: "🔐 This service requires connection to our company VPN. Please install Tailscale from https://tailscale.com and connect to the 'Company' network."
successMessage: "✅ VPN connection verified! Welcome to the secure portal."
```

### Custom Styling

```yaml
customCSS: |
  /* Dark theme */
  body { background: #1a1a1a; color: #fff; }
  .verification-card { background: #2d2d2d; border: 1px solid #444; }
  
  /* Company branding */
  .tailscale-logo { display: none; }
  .header::before { 
    content: url('data:image/svg+xml;base64,...'); /* Your logo */
  }
```

### Additional JavaScript

```yaml
customScript: |
  // Analytics tracking
  gtag('event', 'tailscale_verification_started');
  
  // Additional security checks
  if (navigator.userAgent.includes('bot')) {
    console.warn('Bot detected during verification');
  }
```

##  Migration from IP-Based Plugin

If you're upgrading from the old IP-based version:

1. **Update the plugin configuration:**
   ```yaml
   # Old way:
   tailscaleauth:
     tailscaleRanges: ["100.64.0.0/10"]
   
   # New way:
   tailscale-connectivity:
     testDomain: "your-domain.ts.net"
   ```

2. **Remove IP-related settings:**
   - `tailscaleRanges`
   - `additionalRanges`
   - `headersToCheck`
   - `trustedProxies`

3. **Add domain configuration:**
   - Set `testDomain` to your actual Tailscale domain

4. **Test thoroughly:**
   - The new approach works differently and may behave differently in your environment

##  Performance

- **Verified Requests**: ~0.1ms overhead (cookie check only)
- **Verification Page**: Served instantly with embedded CSS/JS
- **Memory Usage**: Minimal - only stores active session tokens
- **Network Impact**: Client-side connectivity test only

##  Contributing

We welcome contributions! This plugin is open source and community-driven.

### Development Setup

```bash
git clone https://github.com/hhftechnology/tailscale-access
cd tailscale-access
go mod tidy
make test
```

### Testing

```bash
# Run tests
go test -v ./...

# Run with Yaegi (Traefik's interpreter)
yaegi test -v .

# Benchmarks
go test -bench=. -benchmem
```

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Traefik](https://traefik.io/) for the excellent reverse proxy and plugin system
- [Tailscale](https://tailscale.com/) for revolutionizing VPN technology
- The open source community for feedback and contributions

---

**Ready to secure your services the smart way?** Install the Tailscale Connectivity Authentication plugin and never worry about complex IP detection again!