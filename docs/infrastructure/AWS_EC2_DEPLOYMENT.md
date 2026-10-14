# AWS EC2 Deployment

This is an optional AWS EC2 deployment recipe, not evidence that the current production service runs on EC2. The repository's release workflow currently uses a configured Render deployment hook; use this guide only if EC2 is the explicitly chosen deployment target. Confirm which DNS provider is authoritative before editing records. If the domain's nameservers point to Cloudflare, manage its records in Cloudflare. The public request path for this EC2 option is:

`api.pesaguard.co.ke` -> Elastic IP -> host Nginx/TLS -> Docker Nginx -> backend services

## 1. Create the AWS server

In AWS EC2, launch an Ubuntu Server 24.04 LTS instance.

Recommended starting size for the complete Docker Compose stack:

- Instance: `t3.large` (2 vCPU, 8 GiB RAM)
- Storage: at least 50 GiB gp3
- Region: closest to your users and provider integrations
- Key pair: create or select an SSH key pair

Kafka, PostgreSQL, Redis, the webhook receiver, the dashboard API, and Nginx
share this instance. Scale them into managed services or separate instances
before production volume grows.

## 2. Configure the security group

Allow inbound traffic only from:

| Protocol | Port | Source |
|---|---:|---|
| SSH | 22 | Your fixed office/home IP, not `0.0.0.0/0` |
| HTTP | 80 | `0.0.0.0/0` |
| HTTPS | 443 | `0.0.0.0/0` |

Do not expose ports `5000`, `5001`, `5432`, `6379`, `9092`, or `8080` publicly.

## 3. Allocate an Elastic IP

In EC2, allocate an Elastic IP and associate it with the instance. Use this
stable IPv4 address for the DNS record. Do not use the instance's temporary
public IP because it can change after stop/start.

## 4. Point the Hosting.com DNS record

In Hosting.com DNS, create:

```text
Host: api.pesaguard
Type: A
Address: YOUR_AWS_ELASTIC_IP
TTL: 1 hour
```

The resulting hostname is `api.pesaguard.co.ke`.

Verify from your computer:

```powershell
nslookup api.pesaguard.co.ke
```

Wait until it returns the Elastic IP before requesting the TLS certificate.

## 5. Connect to EC2 and install Docker

Replace the key path and Elastic IP with your values:

```bash
ssh -i ./pesaguard.pem ubuntu@YOUR_AWS_ELASTIC_IP
```

On the EC2 server:

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl git nginx certbot python3-certbot-nginx
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu
newgrp docker
sudo systemctl enable --now nginx
```

## 6. Deploy the repository

```bash
git clone YOUR_REPOSITORY_URL ~/pesaguard
cd ~/pesaguard
```

Create the runtime environment file:

```bash
cp .env.example .env
nano .env
```

At minimum, set real values for:

```dotenv
PESAGUARD_API_URL=https://api.pesaguard.co.ke
PESAGUARD_BIND_HOST=0.0.0.0
PESAGUARD_ENVIRONMENT=production
DATABASE_URL_DOCKER=postgresql://pesaguard:CHANGE_ME@postgres:5432/pesaguard
JWT_SECRET_KEY=GENERATE_A_LONG_RANDOM_SECRET
PESAGUARD_PAYLOAD_ENCRYPTION_KEY=GENERATE_A_FERNET_KEY
DARAJA_CONSUMER_KEY=YOUR_VALUE
DARAJA_CONSUMER_SECRET=YOUR_VALUE
DARAJA_SHARED_SECRET=GENERATE_A_LONG_RANDOM_SECRET
PESAGUARD_CORS_ALLOWED_ORIGINS=https://api.pesaguard.co.ke
```

Generate secrets on the server, and do not commit `.env`:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
chmod 600 .env
```

Use the actual generated values in `.env`. The systemd backup service uses a
separate `/etc/pesaguard/backup.env` file for host-level backup credentials.

## 7. Start the Docker backend

Use the AWS overlay. It exposes only `127.0.0.1:8080` to the host Nginx and
removes the direct host exposure of ports 5000 and 5001:

```bash
docker compose \
  -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.aws.yml \
  up -d --build
```

Check service state:

```bash
docker compose -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.aws.yml ps
docker compose -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.aws.yml logs --tail=100 nginx dashboard_api webhook_receiver
```

Test the private router from the EC2 host:

```bash
curl -i -H 'Host: api.pesaguard.co.ke' http://127.0.0.1:8080/health
```

## 8. Configure host Nginx

Replace the default Nginx site:

```bash
sudo rm -f /etc/nginx/sites-enabled/default
sudo nano /etc/nginx/sites-available/pesaguard-api
```

Paste:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name api.pesaguard.co.ke;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

Enable and validate it:

```bash
sudo ln -s /etc/nginx/sites-available/pesaguard-api /etc/nginx/sites-enabled/pesaguard-api
sudo nginx -t
sudo systemctl reload nginx
```

## 9. Enable HTTPS

After DNS resolves to the Elastic IP:

```bash
sudo certbot --nginx \
  -d api.pesaguard.co.ke \
  --redirect \
  --agree-tos \
  -m YOUR_EMAIL_ADDRESS
```

Check renewal:

```bash
sudo certbot renew --dry-run
```

## 10. Verify the public backend

```bash
curl -i https://api.pesaguard.co.ke/health
curl -i https://api.pesaguard.co.ke/metrics
```

The metrics endpoint should require the configured authenticated permission.
Do not test transaction creation with a spoofed `X-Tenant-ID`; use a valid
authenticated principal whose tenant matches the request.

## 11. Enable restart recovery

Create a systemd unit:

```bash
sudo nano /etc/systemd/system/pesaguard.service
```

```ini
[Unit]
Description=PesaGuard Docker stack
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/ubuntu/pesaguard
ExecStart=/usr/bin/docker compose -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.aws.yml up -d
ExecStop=/usr/bin/docker compose -f infra/docker/docker-compose.yml -f infra/docker/docker-compose.aws.yml down
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pesaguard.service
```

## Important production note

This single EC2 instance is a practical first deployment, not a highly available
financial production architecture. Use managed RDS PostgreSQL, ElastiCache
Redis, durable Kafka/MSK, encrypted off-site backups, and a separate worker
capacity plan before high-volume production traffic.
