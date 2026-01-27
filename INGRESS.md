# Pantavisor Ingress Specification

Ingress allows routing external traffic (TCP or HTTP) from the host network into container-provided services. Pantavisor supports two primary patterns for managing Ingress.

## 1. Global Ingress Policy (Integrated)

Managed centrally in \`device.json\`. This is the preferred method for simple port forwarding and path routing without requiring a dedicated proxy container.

### Specification (\`device.json\`)

\`\`\`json
{
  "ingress": [
    {
      "name": "public-api",
      "type": "http",
      "external": "0.0.0.0:80/api",
      "provider": "api-container",
      "service": "api-unix-service"
    },
    {
      "name": "public-https",
      "type": "tcp",
      "external": "0.0.0.0:443",
      "provider": "api-container",
      "service": "api-https-service"
    },
    {
      "name": "ssh-gateway",
      "type": "tcp",
      "external": "0.0.0.0:2222",
      "provider": "shell-container",
      "service": "ssh-service"
    }
  ]
}
\`\`\`

#### Field Definitions:
- \`name\`: A unique identifier for the ingress rule.
- \`type\`: The protocol type (\`tcp\` or \`http\`).
- \`external\`: The host-side listening address and port. For \`http\`, this can include a path prefix (e.g., ":80/api").
- \`provider\`: The name of the container providing the service.
- \`service\`: The name of the service as defined in the provider's \`services.json\`.

#### Conflict Resolution:
Pantavisor validates the global \`ingress\` array at startup. If two rules attempt to bind to the same host port, the entire state is considered invalid, preventing silent port collisions.

---

## 2. Ingress Proxy Container (Advanced)

### Pattern 2b: Isolated Proxy + Integrated Ingress (Recommended for Security)

In this hybrid pattern, the proxy container runs in an isolated network namespace (via IPAM) and does NOT have host network access. External traffic is routed into it via a global ingress rule.

**1. The Ingress Rule (`device.json`):**
```json
{
  "ingress": [
    {
      "name": "nginx-ingress-80",
      "type": "tcp",
      "external": "0.0.0.0:80",
      "provider": "proxy-container",
      "service": "nginx-http"
    },
    {
      "name": "nginx-ingress-443",
      "type": "tcp",
      "external": "0.0.0.0:443",
      "provider": "proxy-container",
      "service": "nginx-https"
    }
  ]
}
```

**2. The Proxy Export (`services.json` inside `proxy-container`):**
```json
{
  "services": [
    {
      "type": "tcp",
      "name": "nginx-http",
      "port": 80
    }
  ]
}
```

**Pros:**
- Proxy is isolated from the host network stack.
- Ports are managed centrally in `device.json` (conflict prevention).
- Proxy can still use IPAM names to talk to backend containers.


For advanced scenarios requiring SSL termination, load balancing, or WAF (e.g., using Nginx or HAProxy).

### Pattern:
1. **The Proxy Container**: Runs a standard proxy (e.g., Nginx) and requests host network access or a public IP via IPAM.
2. **IP Downstreams**: The proxy container talks to backend containers using their container names as hostnames over a shared network pool managed by IPAM.
3. **Configuration**: The proxy configuration is managed via Pantavisor's \`_config\` mechanism.

### Example Nginx Ingress Setup

**Network Configuration (\`device.json\`):**
\`\`\`json
{
  "network": {
    "pools": {
      "internal": { "subnet": "10.0.3.0/24" }
    }
  }
}
\`\`\`

**Backend Container (\`app-1\`) \`args.json\`:**
\`\`\`json
{ "PV_NETWORK_POOL": "internal" }
\`\`\`

**Nginx Container (\`ingress-nginx\`) \`args.json\`:**
\`\`\`json
{ "PV_NETWORK_POOL": "internal" }
\`\`\`

**Nginx configuration (\`_config/ingress-nginx/etc/nginx/conf.d/default.conf\`):**
\`\`\`nginx
server {
    listen 80;
    location / {
        proxy_pass http://app-1:8080;
    }
}
\`\`\`
