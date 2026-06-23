# Railway MCP Server

A remote MCP (Model Context Protocol) server that exposes Railway API operations as tools for Claude and other MCP-capable agents. Part of the [Build from Claude](../README.md) bundle.

## What it does

Lets an agent manage your Railway account end to end: create projects, deploy services from GitHub repos, deploy templates, manage variables and domains, read deploy logs, run Postgres queries, and manage volumes.

## Deploy

This service deploys from the `railway-mcp/` directory of the bundle repo. See the [top-level README](../README.md#deploy) for the one-step bundle deploy. To deploy just this service:

1. New Project → **Deploy from GitHub repo** → pick this repo.
2. Set the service **Root Directory** to `railway-mcp`.
3. Set the two required variables (below) and deploy.

## Required variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RAILWAY_API_TOKEN` | Yes | A Railway API token. Create one at [railway.com/account/tokens](https://railway.com/account/tokens). |
| `AUTH_PASSWORD` | Yes | The password you'll type on the OAuth page when connecting from Claude. Make it long and random. |
| `PUBLIC_URL` | Auto | Set by `railway.toml` to your service's public domain. |
| `DATA_DIR` | Auto | `/app/data` — the mounted volume where OAuth state persists. |
| `DISCORD_WEBHOOK_URL` | No | If set, security/activity alerts are posted here. |
| `MCP_ACTIVITY_ALERTS` | No | `true` to alert on session start and destructive tool calls. |

## Connect it to Claude

Custom connectors are available on Claude's paid plans (Pro/Max/Team/Enterprise).

1. In Railway, copy the service's public URL and add `/mcp` (e.g. `https://railway-mcp-server-production-xxxx.up.railway.app/mcp`).
2. In Claude, open **Settings → Connectors → Add custom connector**.
3. Paste the `/mcp` URL and save.
4. Click **Connect**. Claude opens *this server's* authorization page (the purple "Railway MCP Server" card) — enter your `AUTH_PASSWORD` and authorize.
5. The Railway tools now show up in Claude.

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

- You deploy your own instance with your own `RAILWAY_API_TOKEN`. No tokens are shared.
- OAuth 2.1 (PKCE + dynamic client registration) protects the `/mcp` endpoint; `POST /oauth/authorize` is rate-limited per IP.
- `list-variables` masks values by default so secrets don't land in the chat transcript; raw values require an explicit `reveal: true`.
- OAuth state persists in the `/app/data` volume, surviving redeploys.
- Anyone who can call the tools can act on your Railway account — keep `AUTH_PASSWORD` secret and the deployment private.

## Local development

```bash
npm install
cp .env.example .env   # fill in RAILWAY_API_TOKEN and AUTH_PASSWORD
npm start
```

## License

MIT
