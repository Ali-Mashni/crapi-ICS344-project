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
- 6GB RAM minimum (8GB recommended)
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
curl -L -o docker-compose.yml https://raw.githubusercontent.com/Ali-Mashni/crapi-ICS344-project/copilot/implement-json-security-logging/deploy/docker/docker-compose.yml
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
mkdir -p reverse-proxy logs/nginx
```

### 4.2 Create Nginx Configuration

Create file: `reverse-proxy/nginx.conf`

```bash
cat > reverse-proxy/nginx.conf <<'EOF'
events {}

http {

  # Allow uploads up to 15MB (crAPI UI max is 10MB)
  client_max_body_size 15m;

  # JSON log format (for Splunk ingestion)
  log_format json_combined escape=json
    '{'
      '"time":"$time_iso8601",'
      '"remote_addr":"$remote_addr",'
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

    location / {
      proxy_pass http://crapi-web:80;

      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
  }
}
EOF
```

---

## 5) Add Reverse Proxy + Splunk to docker-compose.yml

Open `docker-compose.yml` and add the following services under `services:`.

**Reverse Proxy Service:**

```bash
  crapi-reverse-proxy:
    image: nginx:alpine
    container_name: crapi_reverse_proxy
    depends_on:
      - crapi-web
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - ./reverse-proxy/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./logs/nginx:/var/log/nginx
```

**Splunk Service:**

```bash
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

## 6) Prevent Bypass (IMPORTANT)

To ensure all traffic is logged, disable direct access to crapi-web.

Find the `crapi-web` service in `docker-compose.yml` and comment out the `ports:` section.

Example:

```bash
  crapi-web:
    # ports:
    #  - "127.0.0.1:8888:80"
    #  - "127.0.0.1:8443:443"
```

This forces everyone to access crAPI via:

`http://127.0.0.1:8080`

---

## 7) Restart Everything

```bash
docker-compose -f docker-compose.yml down
docker-compose -f docker-compose.yml --compatibility up -d
```

**Verify:**

```bash
docker-compose -f docker-compose.yml ps
```

---

## 8) Verify Logging Works

**Open:**

`http://127.0.0.1:8080`

Then check the log file:

```bash
tail -n 10 logs/nginx/access.json
```

You should see JSON entries.

If the file is empty, you are likely browsing `:8888` instead of `:8080`.

---

## 9) Configure Splunk

**Open:**

`http://127.0.0.1:8000`

**Login:**

- Username: `admin`
- Password: `ChangeThisPassword123!`

**Add Log File to Splunk**

1. Go to **Settings** → **Add Data**
2. Choose **Monitor**
3. Choose **Files & Directories**
4. Enter path:

```bash
/data/nginx/access.json
```

5. Create new index:

```bash
nginx
```

6. Choose source type:

```bash
_json
```

7. Finish setup.

---

## 10) Confirm Splunk Is Receiving Logs

In Splunk Search:

```bash
index=nginx
| head 20
```

Then:

```bash
index=nginx
| stats count by method, status
```

If events appear, setup is complete.

---

## 11) Generate Test Traffic

### Enumeration Example

```bash
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://127.0.0.1:8080/api/v2/vehicle/$i"
done
```

**Splunk detection query:**

```bash
index=nginx uri="/api/v2/vehicle/*"
| stats count as hits, dc(uri) as unique_uris by remote_addr
| sort -hits
```