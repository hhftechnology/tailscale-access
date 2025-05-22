# Tailscale Authentication Plugin for Traefik

A middleware plugin that provides secure access control by allowing only Tailscale-connected clients to reach your protected resources. This plugin solves the complex challenge of identifying real client IPs in networking setups where standard IP allowlists fail.

## The Problem This Solves

Standard Traefik middlewares like `ipAllowList` work well in simple networking scenarios where the client IP is directly visible. However, when you're running Tailscale with reverse proxies like Gerbil, Docker network mode sharing, and multiple networking layers, the original Tailscale IP often gets buried or transformed in ways that make it invisible to traditional IP filtering.


## Features

**Intelligent IP Detection**: The plugin doesn't just look at the immediate connection IP. It systematically examines multiple HTTP headers and connection sources to find the real Tailscale client IP, even when it's been transformed by proxies or container networking.

**Tailscale-Aware Logic**: Unlike generic IP filters, this plugin understands Tailscale's networking model and can correctly identify valid Tailscale connections regardless of how they've been routed through your infrastructure.

**Comprehensive Debugging**: When troubleshooting networking issues, the plugin provides detailed logging that shows exactly where it found (or didn't find) the client IP, making it much easier to diagnose complex networking problems.

**Flexible Configuration**: You can customize which IP ranges are considered valid, which headers to examine for client IPs, and how the plugin behaves in different scenarios.

**Production Ready**: The plugin includes proper error handling, validation, and performance optimizations suitable for production environments.

## Installation

Installing this plugin requires adding it to your Traefik static configuration and then referencing it in your dynamic configuration. The process involves two main steps: telling Traefik about the plugin's existence and then configuring how it should behave.

### Step 1: Add to Traefik Static Configuration

In your main Traefik configuration file, add the plugin declaration to the experimental plugins section:

```yaml
# traefik.yml or docker-compose command
experimental:
  plugins:
    tailscale-auth: # This is a user-defined name for your plugin instance
      moduleName: [github.com/hhftechnology/tailscale-access](https://github.com/hhftechnology/tailscale-access)
      version: v1.0.0 # Replace with your plugin's version or local path
```

### Step 2: Configure the Middleware

Create or update your dynamic configuration to define how the middleware should behave:

```yaml
# dynamic-config.yml or rules file
http:
  middlewares:
    tailscale-access-middleware: # User-defined name for this middleware instance
      plugin:
        tailscaleauth: # Use the Go package name 'tailscaleauth' here
          tailscaleRanges:
            - "100.64.0.0/10"  # Standard Tailscale CGNAT range
          additionalRanges:
            - "127.0.0.1/32"   # Allow localhost for testing
          enableDebugLogging: true
          customErrorMessage: "Access denied: Please connect via Tailscale to access this resource"
          headersToCheck:
            - "X-Forwarded-For"
            - "X-Real-IP"
            - "X-Original-Forwarded-For"
            - "CF-Connecting-IP"
```

### Step 3: Apply to Your Routes

Once the middleware is defined, you can apply it to any route that should be protected:

```yaml
http:
  routers:
    protected-service:
      rule: "Host(`myapp.example.com`)"
      service: "my-backend-service"
      middlewares:
        - "tailscale-access-middleware" # Reference the middleware instance name defined above
```

## Configuration Options

Understanding each configuration option helps you tailor the plugin to your specific networking environment and security requirements.

### tailscaleRanges

This array defines which IP address ranges should be considered valid Tailscale connections. The default value covers Tailscale's standard CGNAT range, but you might need to customize this if you're using different network configurations.

```yaml
# Example for the dynamic configuration under 'plugin.tailscaleauth'
# tailscaleauth:
#   tailscaleRanges:
#     - "100.64.0.0/10"     # Standard Tailscale range
#     - "10.0.0.0/8"        # Custom private range if you've configured Tailscale differently
```

The plugin will allow access from any IP address that falls within these ranges. Tailscale typically uses the 100.64.0.0/10 range for its CGNAT implementation, which provides each device with a unique IP in this space.

### additionalRanges

Sometimes you need to allow access from non-Tailscale sources, such as local development environments or trusted proxy servers. This option lets you specify additional IP ranges that should be granted access.

```yaml
# Example for the dynamic configuration under 'plugin.tailscaleauth'
# tailscaleauth:
#   additionalRanges:
#     - "127.0.0.1/32"      # Localhost for development
#     - "192.168.1.0/24"    # Local network for testing
#     - "10.0.0.0/8"        # Corporate network range
```

This is particularly useful during development and testing phases, or when you have legitimate non-Tailscale sources that need access to your protected resources.

### headersToCheck

This configuration tells the plugin which HTTP headers might contain the real client IP address. Different proxy servers and load balancers use different header names to preserve the original client IP information.

```yaml
# Example for the dynamic configuration under 'plugin.tailscaleauth'
# tailscaleauth:
#   headersToCheck:
#     - "X-Forwarded-For"
#     - "X-Real-IP"
#     - "X-Original-Forwarded-For"
#     - "CF-Connecting-IP"
#     - "True-Client-IP"
#     - "X-Client-IP"
```

The plugin will examine these headers in the order you specify them, looking for valid Tailscale IP addresses. This is crucial for setups where the client IP has been transformed by reverse proxies or container networking.

### enableDebugLogging

When set to true, this option provides detailed information about how the plugin is processing each request. This is invaluable for troubleshooting networking issues and understanding how your traffic is being routed.

```yaml
# Example for the dynamic configuration under 'plugin.tailscaleauth'
# tailscaleauth:
#   enableDebugLogging: true
```

The debug output shows which IP addresses were found in which locations, which headers were checked, and what decisions the plugin made. However, you should disable this in production environments to avoid performance impacts and log clutter.

### customErrorMessage

This allows you to customize the message that users see when they're denied access. A clear, helpful message can guide users toward the correct way to access your resources.

```yaml
# Example for the dynamic configuration under 'plugin.tailscaleauth'
# tailscaleauth:
#   customErrorMessage: "Access denied: Please connect via Tailscale to access this resource. Visit [https://tailscale.com/kb/1017/install](https://tailscale.com/kb/1017/install) for setup instructions."
```

## Use Cases and Examples

Understanding when and how to use this plugin helps you apply it effectively in different scenarios.

### Scenario 1: Protecting Internal Services

Suppose you're running internal company tools that should only be accessible to employees with Tailscale installed. Traditional IP allowlists become cumbersome because employees work from different locations with different external IPs.

```yaml
http:
  middlewares:
    company-tailscale-auth:
      plugin:
        tailscaleauth: # Corrected
          tailscaleRanges:
            - "100.64.0.0/10"
          customErrorMessage: "This internal tool requires a company Tailscale connection. Contact IT for setup assistance."
          enableDebugLogging: false  # Disabled for production
```

### Scenario 2: Development Environment Access

For development environments, you might want to allow both Tailscale access and local development access, while still blocking external traffic.

```yaml
http:
  middlewares:
    dev-access:
      plugin:
        tailscaleauth: # Corrected
          tailscaleRanges:
            - "100.64.0.0/10"
          additionalRanges:
            - "127.0.0.1/32"     # Local development
            - "192.168.1.0/24"   # Office network
          enableDebugLogging: true  # Helpful during development
          headersToCheck:
            - "X-Forwarded-For"
            - "X-Real-IP"
```

### Scenario 3: Complex Proxy Setup

When you're using multiple layers of proxies (like Gerbil + Traefik), you need to check additional headers where the real IP might be preserved.

```yaml
http:
  middlewares:
    multi-proxy-tailscale:
      plugin:
        tailscaleauth: # Corrected
          tailscaleRanges:
            - "100.64.0.0/10"
          headersToCheck:
            - "X-Forwarded-For"
            - "X-Real-IP"
            - "X-Original-Forwarded-For"
            - "X-Gerbil-Client-IP"  # Custom header from your proxy
          enableDebugLogging: true
```

## Integration with Middleware Manager

If you're using the Pangolin Middleware Manager, you can add this plugin as a template to make it easily reusable across multiple resources.

Add this to your `templates.yaml` file:

```yaml
middlewares:
  - id: "tailscale-auth-template" # Changed ID for clarity
    name: "Tailscale Authentication"
    type: "plugin"
    config:
      tailscaleauth: # Corrected
        tailscaleRanges:
          - "100.64.0.0/10"
        additionalRanges:
          - "127.0.0.1/32"
        enableDebugLogging: false
        customErrorMessage: "Access denied: Tailscale connection required"
        headersToCheck:
          - "X-Forwarded-For"
          - "X-Real-IP"
          - "X-Original-Forwarded-For"
```

Once this template is loaded, you can apply Tailscale authentication to any resource through the Middleware Manager's web interface, making it as easy as clicking a button to protect your services.

## Troubleshooting

When the plugin isn't working as expected, systematic troubleshooting helps identify where the problem lies in your networking stack.

### Enable Debug Logging First

The most effective way to understand what's happening is to enable debug logging temporarily in your dynamic configuration for the middleware:

```yaml
# Example in your dynamic configuration
# http:
#   middlewares:
#     your-middleware-name:
#       plugin:
#         tailscaleauth:
#           enableDebugLogging: true
#           # ... other settings
```

This will show you exactly what IP addresses the plugin is finding and where it's finding them. Look for log entries like:

```
[TailscaleAuth:my-middleware] Direct connection IP: 172.17.0.1
[TailscaleAuth:my-middleware] Checking header X-Forwarded-For: 100.64.1.100, 172.17.0.1
[TailscaleAuth:my-middleware] Found Tailscale IP in X-Forwarded-For header: 100.64.1.100
[TailscaleAuth:my-middleware] Allowing access for IP: 100.64.1.100
```

### Common Issues and Solutions

**Problem**: The plugin is blocking Tailscale clients
**Solution**: Check if your Tailscale network uses custom IP ranges. Some Tailscale configurations use different subnets, so you might need to add them to `tailscaleRanges`.

**Problem**: Debug logs show the wrong IP being detected
**Solution**: Examine which headers contain the correct IP and adjust the `headersToCheck` configuration. Different proxy setups use different header names.

**Problem**: Plugin allows non-Tailscale connections
**Solution**: Verify that your `tailscaleRanges` and `additionalRanges` are configured correctly. Remove any overly broad ranges that might be allowing unwanted traffic.

**Problem**: No debug logs appearing
**Solution**: Ensure the plugin is actually being applied to your routes. Check that the middleware is correctly referenced in your router configuration, and that the middleware instance using the plugin is correctly defined.

### Verifying Your Tailscale IP Range

To confirm what IP range your Tailscale network uses, connect a device to Tailscale and check its assigned IP:

```bash
# On a Tailscale-connected device
ip addr show tailscale0
# or
tailscale ip -4
```

The IP you see should fall within the ranges configured in your plugin. If it doesn't, you'll need to update your `tailscaleRanges` configuration.

### Local Development Setup

Create a local development environment:

```bash
# Clone or create your plugin repository
mkdir tailscale-access # This directory name should match the last part of your moduleName
cd tailscale-access

# Initialize Go module
go mod init [github.com/hhftechnology/tailscale-access](https://github.com/hhftechnology/tailscale-access)

# Create the basic structure
touch tailscale-access.go # Contains 'package tailscaleauth'
touch tailscale-access_test.go # Contains 'package tailscaleauth_test'
touch .traefik.yml # Describes the plugin to Traefik Pilot
```

### Testing Changes

Run the included tests to verify your changes work correctly:

```bash
go test -v ./...
```

For testing with Traefik's Yaegi interpreter (which is how plugins actually run):

```bash
# Install yaegi for testing
# Ensure you have Go installed, then:
go install [github.com/traefik/yaegi/cmd/yaegi@latest](https://github.com/traefik/yaegi/cmd/yaegi@latest)

# Test with yaegi (from the root of your plugin directory)
yaegi test -v .
```

### Plugin Architecture

Understanding how the plugin works internally helps when making modifications or debugging issues. The plugin follows Traefik's standard middleware pattern, where each HTTP request passes through the `ServeHTTP` method.

The IP detection logic works in layers: first checking the direct connection, then systematically examining HTTP headers for forwarded IP information. This layered approach ensures that the plugin can find Tailscale IPs regardless of how many network hops they've passed through.

The validation logic uses Go's standard `net` package to parse IP addresses and CIDR ranges, ensuring robust and reliable IP matching that handles edge cases correctly.

## Security Considerations

While this plugin significantly improves access control for Tailscale environments, understanding its security implications helps you use it appropriately.

**IP Spoofing**: The plugin relies on IP addresses for authentication, which can potentially be spoofed in certain network configurations. However, when combined with Tailscale's encrypted mesh networking, this provides strong security for most use cases.

**Header Manipulation**: Since the plugin examines HTTP headers to find client IPs, ensure that your proxy configuration doesn't allow external clients to inject or manipulate these headers. Proper proxy configuration should strip untrusted headers from external requests.

**Logging Sensitivity**: Debug logs contain IP address information, which might be considered sensitive in some environments. Ensure that debug logging is disabled in production and that any logs are handled according to your privacy policies.

**Defense in Depth**: This plugin should be part of a broader security strategy rather than the sole security measure. Consider combining it with other authentication methods for highly sensitive resources.

Understanding these considerations helps you deploy the plugin safely while maintaining the security posture your applications require.