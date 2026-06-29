# Build from Claude (or ChatGPT) — Railway + GitHub MCP

A single, self-hosted MCP server that lets you build and ship real apps on Railway straight from a chat interface. Connect it to Claude or ChatGPT (or any MCP-capable agent) and you can write code, commit it to GitHub, and deploy it to Railway without leaving the conversation.

One server, one connector, both toolsets:

- **Railway** — workspaces, projects, services, deploys, variables, domains, logs, Postgres, volumes.
- **GitHub** — repos, files, branches, pull requests (including merge), code search, commits.

Together they're the full loop: GitHub writes the code, Railway ships it.

## How it works

```
  Claude / ChatGPT (or any MCP agent)
        │  remote MCP over HTTPS, OAuth 2.1
        ▼
  your self-hosted "combined" server on Railway
        ├──▶ Railway API   (build & deploy, as the logged-in user)
        └──▶ GitHub API    (read & write code)
```

You deploy your own copy with your own account. Nothing is shared or multi-tenant, and it isn't Claude-specific — any client that speaks remote MCP with OAuth can use it.

## Deploy

The product is the [`combined/`](combined) server — one Railway service exposing both toolsets behind a single `/mcp` endpoint and a single Login-with-Railway flow.

1. **Create a project** in Railway.
2. **Add the service:** New Service → Deploy from GitHub repo → this repo → set **Root Directory** to `combined`.
3. It needs no secrets to start: it authenticates you via **Login with Railway** and acts as your account. It auto-derives its public URL and persists OAuth + GitHub state on a `/app/data` volume.
4. Open the service's public URL in a browser — the landing page walks you (or a newcomer) through connecting it.

Optional service variables are documented in [`combined/README.md`](combined/README.md) and [`combined/.env.example`](combined/.env.example) — notably `RAILWAY_MODE` / `GITHUB_MODE` (capability scoping) and `DISCORD_WEBHOOK_URL` (alerting).

## Connect to your assistant

Custom MCP connectors require a paid plan (Claude Pro/Max/Team/Enterprise; ChatGPT Business/Enterprise for write actions — Plus/Pro are read-only even in developer mode).

1. Copy the service's public URL from Railway and append `/mcp`.
2. **Claude:** Settings → Connectors → Add custom connector → paste the `/mcp` URL → Connect → **Log in with Railway**.
   **ChatGPT:** enable developer mode, add the connector by the same `/mcp` URL, and authorize.
3. The first person to connect locks the server to themselves (or set `ALLOWED_RAILWAY_EMAILS`).
4. **Connect GitHub** (optional, anytime): ask the assistant to run `github-connect`. It walks you through installing the GitHub App and picking repos via device flow — no token to paste. A static `GITHUB_TOKEN` is an alternate fallback.

## Security model

- **Login with Railway, locked to you.** Authenticates the human via Railway's OIDC and only allows its owner (first verified login) or the emails in `ALLOWED_RAILWAY_EMAILS`. Anyone else who finds the URL is denied.
- **No token to paste.** It calls the Railway API *as the logged-in user* via their OAuth session, scoped to the workspace they consent to. `RAILWAY_API_TOKEN` is an advanced, unattended-only override. GitHub uses the `github-connect` device flow (or an optional `GITHUB_TOKEN`).
- **OAuth everywhere.** Assistant ↔ server is OAuth 2.1 (PKCE + dynamic client registration, RFC 8414/9728 metadata); the server ↔ Railway leg also uses PKCE, with mid-session token refresh.
- **Secrets stay out of the chat.** `railway-list-variables` *always* masks values and links to the Railway dashboard to view/edit them. `railway-query-postgres` resolves the database connection string server-side from `projectId`/`serviceId`, so the DSN never enters the transcript.
- **Least privilege.** `RAILWAY_MODE` (`read` / `deploy` / `full`) and `GITHUB_MODE` (`off` / `read` / `write`) gate which tools are even registered. Tools carry MCP `readOnlyHint`/`destructiveHint` annotations.
- **Confirm-before-ship.** Destructive actions (delete, merge-to-prod) require the assistant to summarize and get explicit confirmation, and fire an optional Discord alert (`DISCORD_WEBHOOK_URL` + `MCP_ACTIVITY_ALERTS=true`).
- Keep the deployment private and only connect clients you trust.

## Repository layout

```
combined/                 the server (Node + Express + MCP SDK + Octokit + pg)
  server.mjs              Railway + GitHub tools, OAuth broker, landing page
  tools/volumes.mjs       volume tools
  railway.toml            service config: start cmd, healthcheck, volume
  README.md, .env.example
icon.png / icon.svg       connector icon
```

## License

MIT — see [LICENSE](LICENSE).
