# GitHub MCP Server

A remote MCP (Model Context Protocol) server that exposes GitHub API operations as tools for Claude and other MCP-capable agents. Part of the [Build from Claude](../README.md) bundle.

## What it does

Lets an agent work with your GitHub repos: list/create repos, read/write/patch/delete files, manage branches, open and inspect pull requests, search code, and browse commits and diffs. Paired with the Railway server, this is what lets you write code and ship it from a chat.

## Deploy

This service deploys from the `github-mcp/` directory of the bundle repo. See the [top-level README](../README.md#deploy) for the one-step bundle deploy. To deploy just this service:

1. New Project → **Deploy from GitHub repo** → pick this repo.
2. Set the service **Root Directory** to `github-mcp`.
3. Set the two required variables (below) and deploy.

## Variables

Auth is **Login with Railway** (identity only — it gates *who* may connect). The GitHub API is called with your `GITHUB_TOKEN`. There is no password.

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes | A GitHub Personal Access Token. A **fine-grained** token (Contents + Pull requests + Administration = Read/write, Metadata = Read) is recommended; a **classic** token with the `repo` scope also works. |
| `ALLOWED_RAILWAY_EMAILS` | No | Comma-separated Railway emails allowed to connect. If empty, the **first verified login becomes the owner** and the only one allowed (trust-on-first-use). |
| `RAILWAY_OAUTH_CLIENT_ID` / `RAILWAY_OAUTH_CLIENT_SECRET` | No | A pre-registered OAuth app. If unset, the server **self-registers** via Dynamic Client Registration at boot. |
| `PUBLIC_URL` | Auto | Set by `railway.toml` to your service's public domain. |
| `DATA_DIR` | Auto | `/app/data` — the mounted volume where OAuth state persists. |
| `DISCORD_WEBHOOK_URL` / `MCP_ACTIVITY_ALERTS` | No | Optional Discord alerts on session start and destructive tool calls. |

### Getting a GitHub token

**Fine-grained (recommended)** — [github.com/settings/personal-access-tokens](https://github.com/settings/personal-access-tokens) → **Generate new token** → Repository access: **All repositories** (or select) → Permissions:
- **Metadata:** Read
- **Contents:** Read and write
- **Pull requests:** Read and write
- **Administration:** Read and write — *this is what enables creating repositories*

**Classic (simpler, coarser)** — [github.com/settings/tokens](https://github.com/settings/tokens) → **Generate new token (classic)** → the **`repo`** scope. Note `repo` grants full control of *all* repos you can access (including orgs you belong to), so the fine-grained option above has a smaller blast radius.

## Connect it to Claude

Custom connectors are available on Claude's paid plans (Pro/Max/Team/Enterprise).

1. In Railway, copy the service's public URL and add `/mcp` (e.g. `https://github-mcp-server-production-xxxx.up.railway.app/mcp`).
2. In Claude, open **Settings → Connectors → Add custom connector**.
3. Paste the `/mcp` URL and save.
4. Click **Connect**. Claude sends you to **Login with Railway** — sign in. The first person to do this locks the connector to themselves (unless you set `ALLOWED_RAILWAY_EMAILS`).
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

- **Login with Railway** authenticates the human; the connector is locked to its owner (or `ALLOWED_RAILWAY_EMAILS`). Anyone else who finds the URL is denied.
- The GitHub API is called with your `GITHUB_TOKEN`; Railway login never sees it.
- Claude ↔ server uses OAuth 2.1 (PKCE + dynamic client registration); the server ↔ Railway leg also uses PKCE.
- `get-file` returns raw file contents by design — it will return secrets if you point it at a file that contains them (e.g. a committed `.env`).
- OAuth state persists in the `/app/data` volume, surviving redeploys. Keep the deployment private.

## Local development

```bash
npm install
cp .env.example .env   # PUBLIC_URL must be reachable for the OAuth callback
npm start
```

## License

MIT
