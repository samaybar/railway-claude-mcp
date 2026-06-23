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
2. **Add the Railway server:** New Service → Deploy from GitHub repo → this repo → set **Root Directory** to `railway-mcp`. Set `RAILWAY_API_TOKEN` and `AUTH_PASSWORD`.
3. **Add the GitHub server:** New Service → same repo → set **Root Directory** to `github-mcp`. Set `GITHUB_TOKEN` and `AUTH_PASSWORD`.
4. Each service gets a public domain and a `/app/data` volume (declared in its `railway.toml`) where OAuth state persists across redeploys.

Per-service variables and token instructions are in [`railway-mcp/README.md`](railway-mcp/README.md) and [`github-mcp/README.md`](github-mcp/README.md).

> **One-click is the next step.** This repo is the source; turning it into a single published Railway template (one click deploys both services with variable prompts) is a follow-up done in Railway's template composer. Until then, the two-service flow above is the path.

## Connect to Claude

Custom connectors are available on Claude's paid plans (Pro/Max/Team/Enterprise). For each server:

1. Copy the service's public URL from Railway and append `/mcp`.
2. In Claude: **Settings → Connectors → Add custom connector** → paste the `/mcp` URL → save.
3. Click **Connect**. Claude opens the server's own authorization page — enter that service's `AUTH_PASSWORD` and authorize.
4. The tools appear in Claude. Add both connectors to get the full build-and-ship loop.

## Security model

- **Your credentials, your instance.** Each server holds one token (yours) and is single-user. No multi-tenant credential custody.
- **OAuth 2.1** (PKCE + dynamic client registration, RFC 8414/9728 metadata) protects every `/mcp` endpoint. The login page is rate-limited per IP.
- **Secrets stay out of the chat.** `list-variables` masks values by default; raw values require an explicit `reveal: true`.
- **Optional alerting.** Set `DISCORD_WEBHOOK_URL` + `MCP_ACTIVITY_ALERTS=true` to get a ping on session start and on destructive/critical tool calls.
- These servers can act on your Railway and GitHub accounts. Keep each `AUTH_PASSWORD` strong, keep the deployments private, and only connect clients you trust.

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
