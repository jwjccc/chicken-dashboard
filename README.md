# Server Probe Monitor

A lightweight self-hosted server status monitor inspired by the DStatus demo, trimmed to the requested feature set.

## Kept Sections

### Overview Page

- Top navigation with title and theme toggle.
- Node status summary:
  - total nodes
  - online nodes
  - offline nodes
- Network summary:
  - total inbound traffic
  - total outbound traffic
- Server card view only:
  - server name
  - location/hostname
  - online/offline state
  - CPU usage
  - memory usage
  - disk usage
  - TCP and UDP connection counts
  - inbound/outbound speed
  - detail link

### Server Detail Page

- Server identity and uptime.
- CPU card:
  - CPU usage
  - CPU model
  - core count
  - load average
- Memory and Swap card.
- Disk card:
  - total capacity
  - used space
  - available space
  - usage progress bar
- Network card:
  - TCP and UDP connection counts
  - total inbound and outbound traffic
  - current inbound and outbound speed
- History charts:
  - CPU/memory/swap
  - bandwidth
  - TCP/UDP connection counts

## Removed Sections

- Expiry overview.
- Clear filter.
- Region section.
- Toolbar/control panel.
- Sorting options.
- List view.
- Group view.
- Page settings.
- Footer links/version block.
- Network quality page.
- Network quality link in server detail.
- CPU temperature.
- Full network interface list.
- IP/location/risk scoring.
- Disk IO details.
- Advanced diagnostics.
- Host system information block beyond the minimal identity shown in the hero.

## Run The Hub

Quick install on a new server after publishing this project to GitHub:

```bash
curl -L https://raw.githubusercontent.com/jwjccc/xiaoji-dashboard/main/scripts/install-panel.sh -o install-panel.sh && chmod +x install-panel.sh && env PROBE_REPO_URL=https://github.com/jwjccc/xiaoji-dashboard.git PROBE_REF=main PROBE_PORT=8080 ./install-panel.sh
```

This installs the hub panel as a systemd service. It does not bind other servers as agents; use the admin backend to generate per-server agent install commands after the panel is online.

Manual run:

```bash
cd server-probe-monitor
node hub/server.js
```

Open:

```text
http://127.0.0.1:8080
```

The hub uses only Node.js built-ins. No npm install is required.

## Configure The Hub

Edit:

```text
data/config.json
```

Important fields:

```json
{
  "port": 8080,
  "heartbeatTimeoutSeconds": 45,
  "historyRetentionPoints": 1440,
  "dashboardTitle": "Server Probe Monitor",
  "allowLegacyAgentToken": false,
  "adminUsername": "admin",
  "adminPasswordHash": "scrypt$...",
  "servers": []
}
```

A fresh installation uses `admin` / `admin`. Change the username and password from the backend UI immediately after first login. The backend stores `adminPasswordHash`, not a plaintext password. Backgrounds, connectivity checks, and optional basic features are not enabled until they are configured manually; only the panel port and Agent response URL are initialized automatically. Newly added servers use per-server secrets; keep `allowLegacyAgentToken` disabled unless you intentionally need a temporary legacy migration path.

## Run One Agent Manually

On a monitored Linux server:

```bash
HUB_URL="https://your-monitor.example.com" \
AGENT_TOKEN="server-specific-secret-from-admin" \
SERVER_ID="server-1" \
SERVER_NAME="Server 1" \
SERVER_LOCATION="SG" \
./agent/probe.sh
```

Send one report only:

```bash
HUB_URL="http://127.0.0.1:8080" AGENT_TOKEN="server-specific-secret-from-admin" SERVER_ID="server-1" ./agent/probe.sh once
```

## Install Agent With systemd

The admin backend generates a one-line install command for each server:

```bash
curl -L 'https://your-monitor.example.com/api/agent/install.sh' -o agent.sh && chmod +x agent.sh && env PROBE_HUB_URL='https://your-monitor.example.com' PROBE_AGENT_TOKEN='server-specific-secret-from-admin' PROBE_SERVER_ID='server-1' PROBE_SERVER_NAME='Server 1' PROBE_SERVER_LOCATION='SG' PROBE_INTERVAL='10' ./agent.sh
```

This downloads the public installer from your panel and passes the server-specific secret through environment variables. The installer writes the systemd service and starts the agent.

Manual systemd install after copying the project or just the `agent/` folder:

```bash
sudo HUB_URL="https://your-monitor.example.com" \
  AGENT_TOKEN="server-specific-secret-from-admin" \
  SERVER_ID="server-1" \
  SERVER_NAME="Server 1" \
  SERVER_LOCATION="SG" \
  bash agent/install-systemd.sh
```

## Admin Login And Add Server

Click **后台** in the top-right corner of the dashboard. Log in with `adminUsername` and the configured admin password, then add a server. The backend stores the server metadata and creates a per-server secret. The returned install command includes that secret and should be run on the target server.

Admin login:

```http
POST /api/admin/login
Content-Type: application/json
```

Example body:

```json
{
  "username": "admin",
  "password": "admin"
}
```

Add server and generate install command:

```http
POST /api/admin/servers
Authorization: Bearer <adminSessionToken>
Content-Type: application/json
```

Example body:

```json
{
  "hubUrl": "https://your-monitor.example.com",
  "serverId": "sg-01",
  "serverName": "Singapore VPS",
  "serverLocation": "SG",
  "expiresAt": "2027-01-01",
  "tags": ["prod"],
  "interval": 10
}
```

Run the returned `command` on the target server as a sudo-capable user. The command downloads `/api/agent/probe.sh`, installs a systemd service, and starts reporting to `/api/agent/report`.

## Install Options API

The hub can return the field definitions needed by the admin frontend.

Fetch the field definitions:

```http
GET /api/admin/install-options
```

## Writable Backend APIs

### Agent report

```http
POST /api/agent/report
Authorization: Bearer <serverSecret>
Content-Type: application/json
```

The agent sends CPU, memory, swap, disk, traffic, TCP and UDP connection data.

### Upsert server metadata

```http
POST /api/admin/server
Authorization: Bearer <adminSessionToken>
Content-Type: application/json
```

Example:

```json
{
  "id": "server-1",
  "name": "Singapore VPS",
  "location": "SG",
  "tags": ["prod"]
}
```

This updates `data/config.json`, so the backend is easy to rewrite or integrate with another admin UI later.

## Data Files

- `data/config.json`: editable configuration and server metadata.
- `data/state.json`: latest reports and history, generated by the hub.

## Notes

- The current agent is a Bash Linux probe. It reads `/proc`, `df`, and standard OS files.
- This avoids a Go toolchain requirement while still collecting the requested metrics.
- If you later want PSI, TCP retransmit, Top processes, disk IO, or per-interface breakdowns, the project can be upgraded to a Go agent without changing the dashboard concept.
