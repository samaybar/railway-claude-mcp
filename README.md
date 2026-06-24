# Build from Claude — Railway + GitHub MCP servers

Two small, self-hosted MCP servers that let you build and ship real apps on Railway from a chat interface. Connect them to Claude (or any MCP-capable agent) and you can write code, commit it to GitHub, and deploy it to Railway without leaving the conversation.

- **`railway-mcp/`** — manage Railway: projects, services, deploys, variables, domains, logs, Postgres, volumes.
- **`github-mcp/`** — manage GitHub: repos, files, branches, pull requests, search, commits.

Together they're the full loop: GitHub MCP writes the code, Railway MCP ships it.

## How it works

```
  Claude (or any MCP agent)
        │  remote MCP over HTTPS, OAuth 2.1
        ▼
  your self-hosted servers on Railway
        │
        ├── railway-mcp ──▶ Railway API   (build & deploy)
        └── github-mcp  ──▶ GitHub API    (read & write code)
```

You deploy your own copies with your own credentials. Nothing is shared or multi-tenant, and the servers aren't Claude-specific — any client that speaks remote MCP with OAuth can use them.

## Deploy

Each folder is an independent Railway service with its own `railway.toml`. Deploy them as two services:

1. **Create a project** in Railway.
2. **Add the Railway server:** New Service → Deploy from GitHub repo → this repo → set **Root Directory** to `railway-mcp`. No variables required — it authenticates you via Login with Railway and acts as your account.
3. **Add the GitHub server:** New Service → same repo → set **Root Directory** to `github-mcp`. Set `GITHUB_TOKEN` (the only required variable).
4. Each service gets a public domain and a `/app/data` volume (declared in its `railway.toml`) where OAuth state persists across redeploys.

Per-service variables and token instructions are in [`railway-mcp/README.md`](railway-mcp/README.md) and [`github-mcp/README.md`](github-mcp/README.md).

> **One-click is the next step.** This repo is the source; turning it into a single published Railway template (one click deploys both services with variable prompts) is a follow-up done in Railway's template composer. Until then, the two-service flow above is the path.

## Connect to Claude

Custom connectors are available on Claude's paid plans (Pro/Max/Team/Enterprise). For each server:

1. Copy the service's public URL from Railway and append `/mcp`.
2. In Claude: **Settings → Connectors → Add custom connector** → paste the `/mcp` URL → save.
3. Click **Connect**. Claude sends you to **Login with Railway** — sign in (and, for the Railway server, consent to the workspace scope). The first person to connect locks the server to themselves.
4. The tools appear in Claude. Add both connectors to get the full build-and-ship loop.

## Security model

- **Login with Railway, locked to you.** Each server authenticates the human via Railway's OIDC and only allows its owner (the first verified login) or the emails in `ALLOWED_RAILWAY_EMAILS`. Anyone else who finds the URL is denied.
- **No token to paste (Railway server).** By default it calls the Railway API *as the logged-in user* via their OAuth session, scoped to the workspace they consent to. `RAILWAY_API_TOKEN` is an optional override. (The GitHub server still uses your `GITHUB_TOKEN`, since Railway login can't issue GitHub credentials.)
- **OAuth everywhere.** Claude ↔ server is OAuth 2.1 (PKCE + dynamic client registration, RFC 8414/9728 metadata); the server ↔ Railway leg also uses PKCE.
- **Secrets stay out of the chat.** `list-variables` masks values by default; raw values require an explicit `reveal: true`.
- **Optional alerting.** Set `DISCORD_WEBHOOK_URL` + `MCP_ACTIVITY_ALERTS=true` to get a ping on session start and on destructive/critical tool calls.
- Keep the deployments private and only connect clients you trust.

## Repository layout

```
railway-mcp/      Railway MCP server (Node + Express + MCP SDK)
  server.mjs
  tools/volumes.mjs
  railway.toml    service config: start cmd, healthcheck, volume, PUBLIC_URL
  .env.example
github-mcp/       GitHub MCP server (Node + Express + MCP SDK + Octokit)
  server.mjs
  railway.toml
  .env.example
```

## License

MIT — see [LICENSE](LICENSE).
