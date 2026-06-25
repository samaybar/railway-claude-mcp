# Combined Railway + GitHub MCP Server

One MCP server exposing **both** the Railway and GitHub toolsets behind a single `/mcp` endpoint and a single **Login with Railway** flow — so it's **one connector in Claude** instead of two.

This is the merge of [`railway-mcp/`](../railway-mcp) and [`github-mcp/`](../github-mcp). It's offered as the recommended single-connector option; the two standalone servers remain for anyone who wants them separate.

## What it exposes

- **Railway tools** (always on): workspaces, projects, services, deploys, variables, domains, logs, Postgres, volumes. These call the Railway API **as the logged-in user** (their Login-with-Railway session), or via a static `RAILWAY_API_TOKEN` if set.
- **GitHub tools** (on when `GITHUB_TOKEN` is set): repos, files, branches, pull requests, code search, commits. These call the GitHub API with your `GITHUB_TOKEN`.

If `GITHUB_TOKEN` is omitted, the server runs Railway-only and the GitHub tools simply aren't registered.

## Auth

Identical to the standalone servers: **Login with Railway** (OAuth 2.1 + OIDC, PKCE, dynamic client registration). The first verified login becomes the owner, or set `ALLOWED_RAILWAY_EMAILS`. See the standalone READMEs for the full model. Railway login can't mint a GitHub credential, so GitHub access still requires `GITHUB_TOKEN`.

## Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | No | Enables the GitHub toolset. Recommended: a fine-grained token with Contents + Pull requests + Administration = Read/write and Metadata = Read; a classic `repo`-scope token also works. |
| `RAILWAY_API_TOKEN` | No | Static override; default is to act as the logged-in user. |
| `ALLOWED_RAILWAY_EMAILS` | No | Comma-separated allowed emails; else trust-on-first-use. |
| `RAILWAY_OAUTH_CLIENT_ID` / `_SECRET` | No | Pre-registered OAuth app; else DCR self-registration. |
| `PUBLIC_URL` | Auto | Derived from `RAILWAY_PUBLIC_DOMAIN`. |
| `DATA_DIR` | Auto | `/app/data` volume for OAuth state. |

## Connect to Claude

Settings → Connectors → Add custom connector → paste `https://<your-domain>/mcp` → Connect → Login with Railway. One connector, both toolsets.

## License

MIT
