# GitHub MCP Server

A remote MCP (Model Context Protocol) server that exposes GitHub API operations as tools for Claude and other MCP-capable agents. Part of the [Build from Claude](../README.md) bundle.

## What it does

Lets an agent work with your GitHub repos: list/create repos, read/write/patch/delete files, manage branches, open and inspect pull requests, search code, and browse commits and diffs. Paired with the Railway server, this is what lets you write code and ship it from a chat.

## Deploy

This service deploys from the `github-mcp/` directory of the bundle repo. See the [top-level README](../README.md#deploy) for the one-step bundle deploy. To deploy just this service:

1. New Project → **Deploy from GitHub repo** → pick this repo.
2. Set the service **Root Directory** to `github-mcp`.
3. Set the two required variables (below) and deploy.

## Required variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes | A GitHub Personal Access Token. A **classic** token with the `repo` scope is recommended; fine-grained tokens can't create repositories. |
| `AUTH_PASSWORD` | Yes | The password you'll type on the OAuth page when connecting from Claude. Make it long and random. |
| `PUBLIC_URL` | Auto | Set by `railway.toml` to your service's public domain. |
| `DATA_DIR` | Auto | `/app/data` — the mounted volume where OAuth state persists. |
| `DISCORD_WEBHOOK_URL` | No | If set, security/activity alerts are posted here. |
| `MCP_ACTIVITY_ALERTS` | No | `true` to alert on session start and destructive tool calls. |

### Getting a token

Classic token (recommended): [github.com/settings/tokens](https://github.com/settings/tokens) → **Generate new token (classic)** → select the **repo** scope → generate and copy it immediately.

## Connect it to Claude

Custom connectors are available on Claude's paid plans (Pro/Max/Team/Enterprise).

1. In Railway, copy the service's public URL and add `/mcp` (e.g. `https://github-mcp-server-production-xxxx.up.railway.app/mcp`).
2. In Claude, open **Settings → Connectors → Add custom connector**.
3. Paste the `/mcp` URL and save.
4. Click **Connect**. Claude opens *this server's* authorization page (the dark "GitHub MCP Server" card) — enter your `AUTH_PASSWORD` and authorize.
5. The GitHub tools now show up in Claude.

## Available tools

| Tool | Description |
|------|-------------|
| `check-connection` | Verify GitHub API connectivity |
| `list-repos` | List your repositories |
| `create-repo` | Create a new repository (private by default) |
| `get-repo` | Repository details |
| `list-branches` | List branches |
| `create-branch` | Create a branch |
| `get-file` | Read file contents |
| `create-or-update-file` | Create or overwrite a file |
| `patch-file` | Edit a file by exact-string replace (sends only the change) |
| `delete-file` | Delete a file |
| `list-pull-requests` | List PRs |
| `get-pull-request` | PR details |
| `create-pull-request` | Open a PR |
| `get-diff` | Diff for a PR or between commits |
| `search-code` | Search code across GitHub |
| `list-commits` | List commits |

## Security

- You deploy your own instance with your own `GITHUB_TOKEN`. No tokens are shared.
- OAuth 2.1 (PKCE + dynamic client registration) protects the `/mcp` endpoint; `POST /oauth/authorize` is rate-limited per IP.
- `get-file` returns raw file contents by design — be aware it will return secrets if you point it at a file that contains them (e.g. a committed `.env`).
- Anyone who can call the tools can act on your GitHub account within the token's scope — keep `AUTH_PASSWORD` secret and the deployment private.

## Local development

```bash
npm install
cp .env.example .env   # fill in GITHUB_TOKEN and AUTH_PASSWORD
npm start
```

## License

MIT
