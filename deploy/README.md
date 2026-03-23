# Deploy HELM — Reference Deployment Guide

Deploy a live HELM demo in 3 minutes on any Docker host.

---

## Quick Deploy (DigitalOcean)

### 1. Create a Droplet

```bash
# Using doctl (DigitalOcean CLI)
doctl compute droplet create helm-demo \
  --region nyc3 \
  --size s-2vcpu-4gb \
  --image docker-20-04 \
  --ssh-keys "$(doctl compute ssh-key list --format ID --no-header | head -1)" \
  --wait

# Get the IP
DROPLET_IP=$(doctl compute droplet get helm-demo --format PublicIPv4 --no-header)
echo "Droplet IP: $DROPLET_IP"
```

### 2. Point DNS

Point your domain at `$DROPLET_IP`:
```bash
# Example: demo.helm.mindburn.run → 1.2.3.4
doctl compute domain records create helm.mindburn.run \
  --record-type A \
  --record-name demo \
  --record-data "$DROPLET_IP" \
  --record-ttl 300
```

### 3. Deploy

```bash
ssh root@$DROPLET_IP << 'EOF'
  git clone https://github.com/Mindburn-Labs/helm.git /opt/helm
  cd /opt/helm
  export DEMO_DOMAIN=demo.helm.mindburn.run   # ← your domain
  docker compose -f docker-compose.demo.yml up -d
EOF
```

That's it. Caddy handles TLS automatically via Let's Encrypt.

---

## Quick Deploy (Any Docker Host)

```bash
git clone https://github.com/Mindburn-Labs/helm.git
cd helm

# Local (no TLS, localhost only)
docker compose -f docker-compose.demo.yml up -d

# With TLS (set your domain)
export DEMO_DOMAIN=demo.yourdomain.com
docker compose -f docker-compose.demo.yml up -d
```

---

## What's Running

| Container | Purpose | Port |
|-----------|---------|------|
| `caddy` | Edge proxy (TLS + rate limit) | 80, 443 |
| `helm` | Kernel API + proxy | 8080 (internal) |
| `postgres` | ProofGraph + receipts | 5432 (internal) |
| `reset` | Daily DB reset (04:00 UTC) | — |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_DOMAIN` | `localhost` | Domain for TLS (Caddy) |

---

## Security Notes

- **Demo keys only** — `EVIDENCE_SIGNING_KEY=demo-ephemeral-key`. Never reuse in production.
- **No real connectors** — `HELM_DEMO_MODE=1` disables Stripe, GitHub, deployops.
- **Rate limited** — 60 req/min per IP via Caddy.
- **Request cap** — 1MB max body.
- **Daily reset** — All state cleared at 04:00 UTC.

---

## Manual Reset

```bash
bash deploy/demo-reset.sh
```

---

## Monitoring

```bash
# Health check
curl -s https://demo.helm.mindburn.run/health

# Logs
docker compose -f docker-compose.demo.yml logs -f helm

# Container status
docker compose -f docker-compose.demo.yml ps
```
