# Public API Without A Public IPv4

The backend can be published through Cloudflare Tunnel. The tunnel connects
outbound from the host, so the host does not need a public IPv4 address.

## Cloudflare setup

1. In Cloudflare Zero Trust, create a tunnel and copy its tunnel token.
2. Add a public hostname:
   - Hostname: `api.pesaguard.co.ke`
   - Service: `http://nginx:8080`
3. Do not create an A record for `api.pesaguard`. Cloudflare creates the tunnel
   CNAME target automatically.

## Start the stack

From the repository root, set the token in the shell and start the normal stack
with the tunnel overlay:

```powershell
$env:CLOUDFLARE_TUNNEL_TOKEN = "paste-your-tunnel-token"
docker compose -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.tunnel.yml up -d
```

The overlay routes `/webhook/*` to the webhook receiver on port 5000 and all
other API paths to the dashboard API on port 5001. Cloudflare terminates public
HTTPS; Nginx receives the private tunnel connection on port 8080.
