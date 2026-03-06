# crAPI Lab Setup with Splunk Integration

## Final URLs

- **crAPI (via proxy):** `http://127.0.0.1:8080`
- **Mail Service:** `http://127.0.0.1:8025`
- **Splunk Web:** `http://127.0.0.1:8000`
- **Username:** `admin`
- **Password:** `ChangeThisPassword123!`

---

## 0) Requirements

### Minimum
- Kali Linux
- 6GB RAM minimum (Greater than or equal to 8GB is recommended)
- 10–15GB free disk space

### Required Software
- Docker
- Docker Compose

---

## 1) Install Docker (Kali)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose
```

**Enable Docker:**

```bash
sudo systemctl enable docker --now
```

**(Optional but recommended — allows running docker without sudo)**

```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Verify installation:**

```bash
docker --version
docker-compose version
```

---

## 2) Create Project Workspace

```bash
mkdir -p ~/crapi
cd ~/crapi
```

---

## 3) Download crAPI Docker Compose File

```bash
curl -L -o docker-compose.yml https://raw.githubusercontent.com/Ali-Mashni/crapi-ICS344-project/main/deploy/docker/docker-compose.yml
docker-compose pull
```

**Verify:**

```bash
docker-compose -f docker-compose.yml config --services
```

You should see services such as:
- crapi-web
- crapi-identity
- crapi-community
- etc.

---

## 4) Add Nginx Reverse Proxy with JSON Logging

### 4.1 Create Required Folders

```bash
mkdir -p reverse-proxy logs/nginx logs/app
touch logs/app/identity_security.jsonl logs/app/community_security.jsonl logs/app/workshop_security.jsonl
```

### 4.2 Create Nginx Configuration

Create file: `reverse-proxy/nginx.conf`

```bash
cat > reverse-proxy/nginx.conf <<'EOF'
events {}

http {
    # Allow uploads up to 15MB (crAPI UI max is 10MB)
    client_max_body_size 15m;

    log_format json_combined escape=json
      '{'
        '"time":"$time_iso8601",'
        '"request_id":"$request_id",'
        '"remote_addr":"$remote_addr",'
        '"real_ip":"$http_x_real_ip",'
        '"x_forwarded_for":"$http_x_forwarded_for",'
        '"method":"$request_method",'
        '"uri":"$request_uri",'
        '"status":$status,'
        '"bytes_sent":$bytes_sent,'
        '"duration":"$request_time",'
        '"auth":"$http_authorization",'
        '"referer":"$http_referer",'
        '"user_agent":"$http_user_agent"'
      '}';

    access_log /var/log/nginx/access.json json_combined;

    server {
        listen 80;


        add_header X-Request-ID $request_id;

        location / {
            proxy_pass http://crapi-web:80;

            
            proxy_set_header X-Request-ID $request_id;

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
    
            proxy_set_header Authorization $http_authorization;
            proxy_pass_header Authorization;
        }
    }
}
EOF
```

---

## 5) Add Reverse Proxy + Splunk to docker-compose.yml

Open `docker-compose.yml` and add the following services under `services:`.

**Reverse Proxy Service:**

```yaml
  crapi-reverse-proxy:
    image: nginx:alpine
    container_name: crapi_reverse_proxy
    depends_on:
      - crapi-web
    ports:
      - "8080:80"
    volumes:
      - ./reverse-proxy/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./logs/nginx:/var/log/nginx
```

**Splunk Service:**

```yaml
  splunk:
    image: splunk/splunk:latest
    container_name: crapi_splunk
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
      - SPLUNK_LICENSE_ACCEPT=yes
      - SPLUNK_PASSWORD=ChangeThisPassword123!
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - ./logs/nginx:/data/nginx
      - ./logs/app:/data/app
```

---

## 6) Start Everything

```bash
docker-compose -f docker-compose.yml --compatibility up -d
```

**Verify:**

```bash
docker-compose -f docker-compose.yml ps
```

*Note: It may take a few minutes for Splunk and the database containers to fully initialize.*

---

## 7) Verify Logging Works

**Open in your browser:**

`http://127.0.0.1:8080`

Then check the log file:

```bash
tail -n 10 logs/nginx/access.json
```

You should see JSON entries populating in the terminal.

---

## 8) Configure Splunk

**Open:**

`http://127.0.0.1:8000`

**Login:**

- Username: `admin`
- Password: `ChangeThisPassword123!`

**Add Log File to Splunk**

1. Go to **Settings** → **Add Data** → **Monitor**.
2. Add Nginx access log first:
   ```bash
   /data/nginx/access.json
   ```
3. Create/select index:
   ```bash
   nginx
   ```
4. Finish setup for `access.json` (Splunk will automatically detect the `_json` source type).
5. Add `identity` app log:
   ```bash
   /data/app/identity_security.jsonl
   ```
6. On the **Set Source Type** page for `identity`:
   - Initially choose source type: `_json`
   - Go to the **Timestamp** tab.
   - Set **Extraction:** `Advanced`
   - Set **Timestamp format:** `%Y-%m-%dT%H:%M:%S.%NZ`
   - Set **Timestamp fields:** `timestamp`
   - *After* modifying the timestamp, click **Save As** and set the Name to `crapi_json`.
7. On the **Input Settings** page, create a new index named:
   ```bash
   app
   ```
   Submit and finish the setup for `identity_security.jsonl`.
8. Add the remaining app logs (Go to **Settings** → **Add Data** → **Monitor**):
   ```bash
   /data/app/community_security.jsonl
   ```
9. On the **Set Source Type** page:
    - Ensure the source type is set to `_json` (leave timestamp extraction as automatic).
10. On the **Input Settings** page:
    - Set the Index to `app`.
    - Submit and finish.
11. Repeat steps 8-10 for the final log file:
    ```bash
    /data/app/workshop_security.jsonl
    ```
