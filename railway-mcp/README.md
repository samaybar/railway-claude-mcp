# Railway MCP Server

A remote MCP (Model Context Protocol) server that exposes Railway API operations as tools for Claude and other MCP-capable agents. Part of the [Build from Claude](../README.md) bundle.

## What it does

Lets an agent manage your Railway account end to end: create projects, deploy services from GitHub repos, deploy templates, manage variables and domains, read deploy logs, run Postgres queries, and manage volumes.

## Deploy

This service deploys from the `railway-mcp/` directory of the bundle repo. See the [top-level README](../README.md#deploy) for the one-step bundle deploy. To deploy just this service:

1. New Project → **Deploy from GitHub repo** → pick this repo.
2. Set the service **Root Directory** to `railway-mcp`.
3. Set the two required variables (below) and deploy.

## Variables

Auth is **Login with Railway** — there is no password, and no separate API token is required by default.

| Variable | Required | Description |
|----------|----------|-------------|
| `RAILWAY_API_TOKEN` | No | Optional static API token. If set, the server calls the Railway API with it. If unset (default), it calls the API **as the logged-in user**, using their Login-with-Railway session. |
| `ALLOWED_RAILWAY_EMAILS` | No | Comma-separated Railway emails allowed to connect. If empty, the **first verified login becomes the owner** and the only one allowed (trust-on-first-use). |
| `RAILWAY_OAUTH_CLIENT_ID` / `RAILWAY_OAUTH_CLIENT_SECRET` | No | A pre-registered OAuth app. If unset, the server **self-registers** via Dynamic Client Registration at boot. |
| `RAILWAY_OAUTH_SCOPE` | No | Defaults to `openid email profile offline_access workspace:admin`. |
| `PUBLIC_URL` | Auto | Set by `railway.toml` to your service's public domain. |
| `DATA_DIR` | Auto | `/app/data` — the mounted volume where OAuth state persists. |
| `DISCORD_WEBHOOK_URL` / `MCP_ACTIVITY_ALERTS` | No | Optional Discord alerts on session start and destructive tool calls. |

## Connect it to Claude

Custom connectors are available on Claude's paid plans (Pro/Max/Team/Enterprise).

1. In Railway, copy the service's public URL and add `/mcp` (e.g. `https://railway-mcp-server-production-xxxx.up.railway.app/mcp`).
2. In Claude, open **Settings → Connectors → Add custom connector**.
3. Paste the `/mcp` URL and save.
4. Click **Connect**. Claude sends you to **Login with Railway** — sign in and consent to the workspace scope. The first person to do this locks the connector to themselves (unless you set `ALLOWED_RAILWAY_EMAILS`).
5. The Railway tools now show up in Claude, acting as your Railway account.

## Available tools

| Tool | Description |
|------|-------------|
| `check-railway-status` | Verify API connectivity and auth |
| `list-projects` | List all your Railway projects |
| `create-project` | Create a new project |
| `get-project` | Project details incl. environments and services |
| `list-services` | List services in a project |
| `create-service-from-github` | Create a service from a GitHub repo |
| `delete-service` | Delete a service |
| `list-variables` | List a service's variables (**values masked by default**; `reveal: true` for raw) |
| `set-variables` | Set service variables |
| `get-logs` | Get deployment logs |
| `list-deployments` | List recent deployments |
| `redeploy-service` | Trigger a redeployment |
| `generate-domain` | Generate a Railway domain for a service |
| `create-environment` | Create a new environment |
| `deploy-template` | Search and deploy Railway templates |
| `query-postgres` | Run SQL against a PostgreSQL database |
| `create-volume` / `list-volumes` / `delete-volume` | Manage volumes |

## Security

- **Login with Railway** authenticates the human; the connector is locked to its owner (or `ALLOWED_RAILWAY_EMAILS`). Anyone else who finds the URL is denied.
- By default the server acts as the **logged-in user** via their OAuth session (scoped to the workspace they consent to) — no long-lived token to leak.
- Claude ↔ server uses OAuth 2.1 (PKCE + dynamic client registration); the server ↔ Railway leg also uses PKCE.
- `list-variables` masks values by default so secrets don't land in the chat transcript; raw values require an explicit `reveal: true`.
- OAuth state (client registration, session tokens, owner) persists in the `/app/data` volume, surviving redeploys. Keep the deployment private.

## Local development

```bash
npm install
cp .env.example .env   # PUBLIC_URL must be reachable for the OAuth callback
npm start
```

## License

MIT
