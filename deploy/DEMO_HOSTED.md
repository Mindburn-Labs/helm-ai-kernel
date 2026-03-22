# Hosted Demo Deployment (demo.mindburn.org)

This guide documents the deployment procedure for the public hosted demo of HELM OSS v1.0.

**Target Environment:** DigitalOcean Droplet (Ubuntu 24.04 LTS, Docker CE)
**Domain:** `demo.mindburn.org`

---

## 1. Infrastructure Setup

### Create Droplet

Create a basic droplet (2 vCPU, 4GB RAM recommended for stability under load).

```bash
doctl compute droplet create helm-demo \
    --region sfo3 \
    --image ubuntu-24-04-x64 \
    --size s-2vcpu-4gb \
    --ssh-keys <your-key-id>
```

### DNS Configuration

Point `demo.mindburn.org` (A record) to the Droplet's public IP.

### Firewall (UFW)

Ensure only necessary ports are open:

- 22 (SSH)
- 80 (HTTP - required for ACME challenges)
- 443 (HTTPS)

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

---

## 2. Application Deployment

The deployment uses `docker-compose.demo.yml` which stands up:

- **Caddy**: Edge proxy, TLS termination, rate limiting.
- **Postgres**: Persistence layer (reset daily).
- **HELM Kernel**: The core application in `HELM_DEMO_MODE=1`.

### Initial Deployment

1. **SSH into the host**:

   ```bash
   ssh root@demo.mindburn.org
   ```

2. **Clone Repository**:

   ```bash
   git clone https://github.com/Mindburn-Labs/helm-oss.git /opt/helm
   cd /opt/helm
   ```

3. **Configure Environment**:
   Create a `.env` file or set variables directly.

   ```bash
   export DEMO_DOMAIN=demo.mindburn.org
   export HELM_DEMO_MODE=1
   ```

4. **Start Services**:
   ```bash
   docker compose -f docker-compose.demo.yml up -d --build
   ```

### Logs & Monitoring

View logs for all services:

```bash
docker compose -f docker-compose.demo.yml logs -f
```

View Caddy access/error logs:

```bash
docker compose -f docker-compose.demo.yml logs -f caddy
```

---

## 3. Verification

Run the included smoke test script to verify all endpoints:

```bash
bash scripts/demo/smoke.sh https://demo.mindburn.org
```

---

## 4. Maintenance

### State Reset

The database is automatically reset every 24 hours by the `cron` container defined in `docker-compose.demo.yml`.

To manually reset the state:

```bash
bash deploy/demo-reset.sh
```

### Updates

To deploy the latest code:

```bash
cd /opt/helm
git pull origin main
docker compose -f docker-compose.demo.yml up -d --build helm
```
