# Railway + GitHub MCP Server

One MCP server exposing **both** the Railway and GitHub toolsets behind a single `/mcp` endpoint and a single **Login with Railway** flow — so it's **one connector** in Claude or ChatGPT.

## What it exposes

- **Railway tools**: workspaces, projects, services, deploys, variables, domains, logs, Postgres, volumes. These call the Railway API **as the logged-in user** (their Login-with-Railway session), or via a static `RAILWAY_API_TOKEN` if set.
- **GitHub tools**: repos, files, branches, pull requests (including merge), code search, commits. The tools are always listed; until GitHub is connected they return a friendly "run `github-connect` first" message.
- **`search` / `fetch`**: read-only tools for ChatGPT connector compatibility (search across your Railway projects + GitHub repos).

GitHub is optional — turn it on with the **`github-connect`** tool (GitHub App device flow, no token to paste) or a static `GITHUB_TOKEN`. Set `GITHUB_MODE=off` to hide GitHub entirely.

## Auth

**Login with Railway** (OAuth 2.1 + OIDC, PKCE, dynamic client registration). The first verified login becomes the owner, or set `ALLOWED_RAILWAY_EMAILS`. The session token is refreshed automatically mid-session. Railway login can't mint a GitHub credential, so GitHub access is granted separately via `github-connect` (or `GITHUB_TOKEN`).

## Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RAILWAY_MODE` | No | Railway capability: `read`, `deploy` (default), or `full` (adds delete). |
| `GITHUB_MODE` | No | GitHub capability: `off`, `read`, or `write` (default). `off` hides GitHub entirely. |
| `GITHUB_TOKEN` | No | Optional **static** GitHub token (fallback). The preferred way to turn on GitHub is the **`github-connect`** tool (GitHub App device flow). Token form: fine-grained with Contents + Pull requests + Administration = R/W, Metadata = Read; or classic `repo`. |
| `RAILWAY_API_TOKEN` | No | **Leave blank for normal use.** Default is to act as the logged-in user, with the session refreshed automatically. Set this only for unattended or shared deployments (no human to reconnect, or one fixed service identity). Use an account token, not a project token. |
| `ALLOWED_RAILWAY_EMAILS` | No | Comma-separated allowed emails; else trust-on-first-use. |
| `RAILWAY_OAUTH_CLIENT_ID` / `_SECRET` | No | Pre-registered OAuth app; else DCR self-registration. |
| `GITHUB_OAUTH_CLIENT_ID` / `GITHUB_APP_SLUG` | No | The GitHub App that `github-connect` uses (defaults baked in). |
| `PUBLIC_URL` | Auto | Derived from `RAILWAY_PUBLIC_DOMAIN`. |
| `DATA_DIR` | Auto | `/app/data` volume for OAuth + GitHub token state. |

## Connect

- **Claude:** Settings → Connectors → Add custom connector → paste `https://<your-domain>/mcp` → Connect → Login with Railway.
- **ChatGPT:** enable developer mode, add the same `/mcp` URL, and authorize. (Write actions require a Business/Enterprise plan; Plus/Pro connectors are read-only.)

One connector, both toolsets.

## License

MIT
