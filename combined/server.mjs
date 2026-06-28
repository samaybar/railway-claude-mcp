import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { GraphQLClient, gql } from "graphql-request";
import pg from "pg";
import { registerVolumeTools } from "./tools/volumes.mjs";
import { Octokit } from "@octokit/rest";

const PORT = parseInt(process.env.PORT || "3000", 10);
// Optional static API token. If set, the server calls the Railway API with THIS
// token (acting as its owner). If unset (the default), the server calls the API
// as the connecting user, using the access token from their Login-with-Railway
// session. This is what removes the need to paste a separate token.
const RAILWAY_API_TOKEN = process.env.RAILWAY_API_TOKEN || "";
// Prefer an explicit PUBLIC_URL; otherwise derive it from Railway's
// auto-injected RAILWAY_PUBLIC_DOMAIN (so the OAuth callback is correct with
// zero config); fall back to localhost for local dev.
const PUBLIC_URL = (
  process.env.PUBLIC_URL ||
  (process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${PORT}`)
).replace(/\/$/, "");
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";

// --- Login with Railway (OAuth 2.0 / OIDC) ---
const RAILWAY_OIDC = {
  authorize: "https://backboard.railway.com/oauth/auth",
  token: "https://backboard.railway.com/oauth/token",
  userinfo: "https://backboard.railway.com/oauth/me",
  register: "https://backboard.railway.com/oauth/register",
};
const RAILWAY_CALLBACK = `${PUBLIC_URL}/oauth/railway/callback`;
// openid/email/profile = identity; offline_access = refresh token;
// workspace:admin = let the agent manage the user's Railway workspace.
const RAILWAY_OAUTH_SCOPE =
  process.env.RAILWAY_OAUTH_SCOPE ||
  "openid email profile offline_access workspace:admin";
// Optional: pre-registered OAuth app credentials. If unset, the server
// self-registers via Dynamic Client Registration at boot.
const RAILWAY_OAUTH_CLIENT_ID = process.env.RAILWAY_OAUTH_CLIENT_ID || "";
const RAILWAY_OAUTH_CLIENT_SECRET = process.env.RAILWAY_OAUTH_CLIENT_SECRET || "";
// Railway emails allowed to use this connector. If empty, the first verified
// login becomes the owner (trust-on-first-use) and is the only one allowed.
const ALLOWED_RAILWAY_EMAILS = (process.env.ALLOWED_RAILWAY_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// GitHub: tools call the GitHub API using either a connected GitHub App token
// (obtained via the `github-connect` device flow) or a static GITHUB_TOKEN PAT.
// GITHUB_TOKEN is an optional fallback; the preferred path is github-connect.
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
// The Railway Claude MCP GitHub App (device flow). client_id is public.
const GITHUB_OAUTH_CLIENT_ID =
  process.env.GITHUB_OAUTH_CLIENT_ID || "Iv23liV2s2zp1qdWMYdq";
const GITHUB_APP_SLUG = process.env.GITHUB_APP_SLUG || "railway-github-claude-mcp";
// Railway's OWN first-party GitHub App (separate from this connector's app) — the
// one Railway uses to deploy from repos. Slug is "railway-app" in prod (see
// backboard RAILWAY_BOT_NAME). This deep link drops the user straight into the
// install/configure flow so they can grant repo access. Overridable for self-hosters.
const RAILWAY_GITHUB_APP_URL =
  process.env.RAILWAY_GITHUB_APP_URL ||
  "https://github.com/apps/railway-app/installations/new";
const GITHUB_DEVICE = {
  code: "https://github.com/login/device/code",
  token: "https://github.com/login/oauth/access_token",
};

// Capability scoping (least privilege), one knob per provider:
//   RAILWAY_MODE = read | deploy (default) | full   (full adds delete)
//   GITHUB_MODE  = off | read | write (default)     (off hides GitHub entirely)
const RAILWAY_MODE = ["read", "deploy", "full"].includes(
  (process.env.RAILWAY_MODE || "").toLowerCase()
)
  ? process.env.RAILWAY_MODE.toLowerCase()
  : "deploy";
const GITHUB_MODE = ["off", "read", "write"].includes(
  (process.env.GITHUB_MODE || "").toLowerCase()
)
  ? process.env.GITHUB_MODE.toLowerCase()
  : "write";

// Parse a truthy env var: accepts true/1/yes/on (case-insensitive).
// Anything else (including unset) is falsy. Defaults to OFF so merging this
// does not suddenly flood the channel.
function parseBool(v) {
  if (!v) return false;
  return ["true", "1", "yes", "on"].includes(String(v).trim().toLowerCase());
}
const MCP_ACTIVITY_ALERTS = parseBool(process.env.MCP_ACTIVITY_ALERTS);

// ---------------------------------------------------------------------------
// Persistent OAuth storage
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.DATA_DIR || "./data";
const STORE_PATH = path.join(DATA_DIR, "auth-store.json");

const registeredClients = new Map();
const authCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

// This server's own OAuth-client registration with Railway (from DCR or env).
// { client_id, client_secret, token_endpoint_auth_method }
let railwayClientReg = null;
// Trust-on-first-use owner when ALLOWED_RAILWAY_EMAILS is empty: { sub, email }.
let owner = null;
// In-flight logins: railwayState -> { claudeClientId, claudeRedirectUri,
// claudeState, claudeCodeChallenge, railwayVerifier, createdAt }.
const pendingAuth = new Map();
const PENDING_AUTH_TTL = 10 * 60 * 1000;

// Connected GitHub App token (from the github-connect device flow):
// { accessToken, refreshToken, expiresAt, login }. Persisted to the volume.
let githubAuth = null;
// In-flight device-flow poll: { device_code, expiresAt }.
let pendingGitHub = null;

const ACCESS_TOKEN_TTL = 7 * 24 * 60 * 60 * 1000;
const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60 * 1000;
const AUTH_CODE_TTL = 5 * 60 * 1000;

function loadStore() {
  try {
    if (!fs.existsSync(STORE_PATH)) return;
    const data = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    const now = Date.now();
    for (const [k, v] of data.clients || []) registeredClients.set(k, v);
    for (const [k, v] of data.accessTokens || []) {
      if (v.expiresAt > now) accessTokens.set(k, v);
    }
    for (const [k, v] of data.refreshTokens || []) {
      if (v.expiresAt > now) refreshTokens.set(k, v);
    }
    if (data.railwayClientReg) railwayClientReg = data.railwayClientReg;
    if (data.owner) owner = data.owner;
    if (data.github) githubAuth = data.github;
    console.log(
      `Loaded ${registeredClients.size} clients, ${accessTokens.size} access tokens, ${refreshTokens.size} refresh tokens` +
        (owner ? `, owner=${owner.email}` : "")
    );
  } catch (err) {
    console.error("Failed to load auth store, starting fresh:", err.message);
  }
}

function saveStore() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const data = {
      clients: [...registeredClients.entries()],
      accessTokens: [...accessTokens.entries()],
      refreshTokens: [...refreshTokens.entries()],
      railwayClientReg,
      owner,
      github: githubAuth,
    };
    fs.writeFileSync(STORE_PATH, JSON.stringify(data), "utf-8");
  } catch (err) {
    console.error("Failed to save auth store:", err.message);
  }
}

loadStore();

// ---------------------------------------------------------------------------
// Discord alerting (fire-and-forget)
// ---------------------------------------------------------------------------
// Debounce repeated alerts for the same dedupeKey to avoid spam.
const lastAlertAt = new Map();
const ALERT_DEBOUNCE_MS = 60 * 1000; // 1 minute

function sendDiscordAlert({ title, description, fields = [], color = 0xED4245, dedupeKey, dedupeMs }) {
  if (!DISCORD_WEBHOOK_URL) return;

  if (dedupeKey) {
    const window = dedupeMs || ALERT_DEBOUNCE_MS;
    const last = lastAlertAt.get(dedupeKey) || 0;
    if (Date.now() - last < window) return;
    lastAlertAt.set(dedupeKey, Date.now());
  }

  const payload = {
    username: "MCP Security",
    embeds: [
      {
        title,
        description,
        color,
        fields,
        timestamp: new Date().toISOString(),
        footer: { text: "railway-mcp-server" },
      },
    ],
  };

  // Fire and forget. Do not await; do not let alert failures break the request.
  fetch(DISCORD_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch((err) => {
    console.error("[alert] Discord webhook failed:", err.message);
  });
}

// ---------------------------------------------------------------------------
// Rate limiter for POST /oauth/authorize
// ---------------------------------------------------------------------------
// Sliding-window, two-tier, keyed by IP. In-memory only.
const RATE_LIMIT_PER_MINUTE = 5;
const RATE_LIMIT_PER_HOUR = 20;
const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

const attemptsByIp = new Map(); // ip -> array of timestamps (ms)

function pruneAttempts(timestamps, now) {
  let i = 0;
  while (i < timestamps.length && timestamps[i] < now - HOUR_MS) i++;
  return i === 0 ? timestamps : timestamps.slice(i);
}

function checkRateLimit(ip) {
  const now = Date.now();
  const pruned = pruneAttempts(attemptsByIp.get(ip) || [], now);

  const inLastMinute = pruned.filter((t) => t >= now - MINUTE_MS).length;
  const inLastHour = pruned.length;

  if (inLastMinute >= RATE_LIMIT_PER_MINUTE) {
    return { limited: true, retryAfter: 60, window: "minute", count: inLastMinute };
  }
  if (inLastHour >= RATE_LIMIT_PER_HOUR) {
    return { limited: true, retryAfter: 3600, window: "hour", count: inLastHour };
  }
  return { limited: false, inLastMinute, inLastHour };
}

function recordAttempt(ip) {
  const now = Date.now();
  const pruned = pruneAttempts(attemptsByIp.get(ip) || [], now);
  pruned.push(now);
  attemptsByIp.set(ip, pruned);
}

// Periodically reap stale IP entries to keep memory bounded.
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of attemptsByIp.entries()) {
    const pruned = pruneAttempts(timestamps, now);
    if (pruned.length === 0) attemptsByIp.delete(ip);
    else attemptsByIp.set(ip, pruned);
  }
}, 10 * MINUTE_MS).unref();

// ---------------------------------------------------------------------------
// MCP activity logging / alerting
// ---------------------------------------------------------------------------
// Gated on MCP_ACTIVITY_ALERTS being truthy AND DISCORD_WEBHOOK_URL being set.

// Tools flagged here generate a Discord alert on invocation. Most are
// state-changing. Two exceptions are listed here even though they only *read*:
//   - railway-query-postgres: SQL is unconstrained; can be read OR write, always alert
//   - railway-list-variables: returns plaintext env var values (including secrets);
//     effectively a secrets exfiltration tool, always alert
const DESTRUCTIVE_TOOLS = new Set([
  "railway-create-project",
  "railway-create-environment",
  "railway-create-service-from-github",
  "railway-delete-service",
  "railway-set-variables",
  "railway-list-variables",
  "railway-redeploy-service",
  "railway-deploy-template",
  "railway-generate-domain",
  "railway-query-postgres",
  "railway-create-volume",
  "railway-delete-volume",
  "github-merge-pull-request",
]);

// Tools that get an extra-attention red color rather than orange.
// railway-list-variables is critical because anyone calling it with reveal=true can
// dump every secret on the service in one call (API keys, DB connection
// strings, etc). Values are masked by default.
const CRITICAL_TOOLS = new Set([
  "railway-delete-service",
  "railway-delete-volume",
  "railway-set-variables",
  "railway-list-variables",
  "railway-query-postgres",
  "github-merge-pull-request",
]);

const SESSION_ALERT_DEBOUNCE_MS = HOUR_MS;

function tokenKey(token) {
  // 8-char prefix of sha256 is plenty for deduplication; not used for auth.
  return sha256(token).toString("hex").slice(0, 8);
}

function truncate(s, n) {
  if (s === undefined || s === null) return "";
  const str = String(s);
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

// Per-tool: produce a short, human-readable summary of the important args.
// Kept to one line so the Discord embed stays compact.
function extractArgSummary(toolName, args = {}) {
  const a = args || {};
  switch (toolName) {
    case "railway-create-project":
      return `name=${a.name || "?"}`;
    case "railway-create-environment":
      return `project=${a.projectId || "?"} name=${a.name || "?"}`;
    case "railway-create-service-from-github":
      return `project=${a.projectId || "?"} repo=${a.repo || "?"}${a.branch ? `@${a.branch}` : ""}`;
    case "railway-delete-service":
      return `service=${a.serviceId || "?"}`;
    case "railway-set-variables": {
      const keys = a.variables ? Object.keys(a.variables) : [];
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"} vars=[${keys.join(", ")}]`;
    }
    case "railway-list-variables":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"}${a.environmentId ? ` env=${a.environmentId}` : ""}`;
    case "railway-redeploy-service":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"}`;
    case "railway-deploy-template":
      return `template=${a.templateId || "?"}${a.projectId ? ` project=${a.projectId}` : " (new project)"}`;
    case "railway-generate-domain":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"}${a.targetPort ? ` port=${a.targetPort}` : ""}`;
    case "railway-query-postgres": {
      // Show the first line of the SQL so you can eyeball SELECT vs. DROP
      // without the full payload bleeding into chat.
      const sql = (a.sql || "").replace(/\s+/g, " ").trim();
      return `sql=${truncate(sql, 160)}`;
    }
    case "railway-create-volume":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"} mount=${a.mountPath || "?"}`;
    case "railway-delete-volume":
      return `volume=${a.volumeId || "?"}`;
    case "github-merge-pull-request":
      return `repo=${a.owner || "?"}/${a.repo || "?"} PR#${a.pull_number ?? "?"}${a.merge_method ? ` (${a.merge_method})` : ""}`;
    default:
      return "";
  }
}

function logMcpActivity({ req, token, body }) {
  const method = body?.method;
  const ip = req.ip || "unknown";
  const ua = req.headers["user-agent"] || "unknown";

  if (!method) return;

  // Minimal console trace for all activity.
  if (method === "tools/call") {
    const toolName = body?.params?.name || "?";
    console.log(`[MCP] tools/call name=${toolName} ip=${ip}`);
  } else {
    console.log(`[MCP] method=${method} ip=${ip}`);
  }

  if (!MCP_ACTIVITY_ALERTS) return;

  // --- Session start ---
  if (method === "initialize") {
    const clientInfo = body?.params?.clientInfo || {};
    const clientName = clientInfo.name || "unknown";
    const clientVersion = clientInfo.version || "";
    sendDiscordAlert({
      title: "🔵 MCP session started",
      description: "A client successfully initialized an MCP session.",
      color: 0x5865F2, // blurple
      fields: [
        { name: "Client", value: truncate(`${clientName} ${clientVersion}`.trim(), 128), inline: true },
        { name: "IP", value: `\`${ip}\``, inline: true },
        { name: "Token ID", value: `\`${tokenKey(token)}\``, inline: true },
        { name: "User-Agent", value: truncate(ua, 256), inline: false },
      ],
      dedupeKey: `mcp_session:${tokenKey(token)}`,
      dedupeMs: SESSION_ALERT_DEBOUNCE_MS,
    });
    return;
  }

  // --- Destructive tool calls ---
  if (method === "tools/call") {
    const toolName = body?.params?.name;
    if (!toolName || !DESTRUCTIVE_TOOLS.has(toolName)) return;

    const args = body?.params?.arguments || {};
    const summary = extractArgSummary(toolName, args);
    const isCritical = CRITICAL_TOOLS.has(toolName);

    sendDiscordAlert({
      title: isCritical ? "🔴 MCP critical tool called" : "🟠 MCP write tool called",
      description: `Tool: \`${toolName}\``,
      color: isCritical ? 0xED4245 : 0xE67E22, // red : orange
      fields: [
        ...(summary ? [{ name: "Arguments", value: truncate(summary, 512), inline: false }] : []),
        { name: "IP", value: `\`${ip}\``, inline: true },
        { name: "Token ID", value: `\`${tokenKey(token)}\``, inline: true },
        { name: "User-Agent", value: truncate(ua, 256), inline: false },
      ],
      // No dedupe: every write gets its own ping.
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function generateId(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function base64url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function verifyPkce(codeVerifier, storedChallenge) {
  const computed = base64url(sha256(codeVerifier));
  return computed === storedChallenge;
}

function toolResponse(text) {
  return { content: [{ type: "text", text }] };
}

// Format a caught error for a tool response. A Railway auth failure (after a
// failed refresh) carries a ready-to-read reconnect message, so we surface it
// as-is instead of burying it under a "Failed to X" prefix. Everything else
// keeps the prefix so the user knows which operation failed.
function toolError(prefix, error) {
  if (error?.name === "RailwayAuthError") return toolResponse(error.message);
  return toolResponse(`${prefix}: ${error?.message ?? String(error)}`);
}

// Mask a variable value so secrets don't bleed into the chat transcript.
// We can't reliably tell a secret apart from a benign value, so we mask
// everything by default and let the caller opt into raw values per call.
function maskValue(value) {
  const s = String(value ?? "");
  if (s.length === 0) return "(empty)";
  return `${"•".repeat(Math.min(s.length, 12))} (${s.length} chars)`;
}

// ---------------------------------------------------------------------------
// MCP Server with Railway tools
// ---------------------------------------------------------------------------
// `railwayToken` is the bearer used for every Railway API call in this request:
// either the static RAILWAY_API_TOKEN override or the connecting user's
// Login-with-Railway access token (resolved + refreshed per request).
function createRailwayMcpServer(railwayToken, githubToken, mcpToken) {
  const server = new McpServer(
    {
      name: "railway-github-mcp",
      title: "Railway + GitHub MCP (Remote)",
      version: "1.0.0",
    },
    { capabilities: { logging: {} } }
  );

  // --- Capability gating (RAILWAY_MODE / GITHUB_MODE) ---
  // Wrap tool registration so disallowed tools are simply never registered.
  // Tools not in TOOL_GROUP (Railway read tools, railway-status, etc.)
  // are always allowed. Provider modes:
  //   railwayCan.deploy/del ; githubCan.read/write
  const railwayCan = {
    deploy: RAILWAY_MODE === "deploy" || RAILWAY_MODE === "full",
    del: RAILWAY_MODE === "full",
  };
  const githubCan = {
    read: GITHUB_MODE === "read" || GITHUB_MODE === "write",
    write: GITHUB_MODE === "write",
  };
  const TOOL_GROUP = {
    "railway-create-project": "rwd", "railway-create-environment": "rwd", "railway-set-variables": "rwd",
    "railway-create-service-from-github": "rwd", "railway-deploy-template": "rwd", "railway-redeploy-service": "rwd",
    "railway-generate-domain": "rwd", "railway-create-volume": "rwd", "railway-query-postgres": "rwd",
    "railway-delete-service": "rwx", "railway-delete-volume": "rwx",
    "github-connect": "ghr", "github-status": "ghr", "github-check-connection": "ghr",
    "github-list-repos": "ghr", "github-get-repo": "ghr", "github-list-branches": "ghr", "github-get-file": "ghr",
    "github-list-pull-requests": "ghr", "github-get-pull-request": "ghr", "github-search-code": "ghr",
    "github-list-commits": "ghr", "github-get-diff": "ghr",
    "github-create-repo": "ghw", "github-create-or-update-file": "ghw", "github-patch-file": "ghw",
    "github-delete-file": "ghw", "github-create-branch": "ghw", "github-create-pull-request": "ghw",
    "github-merge-pull-request": "ghw",
  };
  const allowedTool = (g) =>
    g == null
      ? true
      : g === "rwd"
      ? railwayCan.deploy
      : g === "rwx"
      ? railwayCan.del
      : g === "ghr"
      ? githubCan.read
      : g === "ghw"
      ? githubCan.write
      : true;
  const _registerTool = server.tool.bind(server);
  server.tool = (name, ...rest) =>
    allowedTool(TOOL_GROUP[name]) ? _registerTool(name, ...rest) : undefined;

  // Mutable bearer: a long MCP session can outlive the access token, so we may
  // swap in a refreshed token mid-session and rebuild the client.
  let currentRailwayToken = railwayToken;
  let railwayClient = new GraphQLClient(
    "https://backboard.railway.com/graphql/v2",
    {
      headers: {
        Authorization: `Bearer ${currentRailwayToken}`,
        "x-source": "railway-mcp-server-remote",
      },
    }
  );

  // A logged-out/expired Railway session surfaces as a GraphQL "Not Authorized"
  // error rather than an HTTP 401, so match on the message.
  function isNotAuthorized(err) {
    const m = String(err?.message || err || "");
    return /not authorized/i.test(m);
  }

  // Raised when a Railway call can't be authorized even after a refresh attempt.
  // Tools catch this and return a clear, actionable reconnect message instead of
  // leaking a raw GraphQL error (which renders as an empty/confusing response).
  class RailwayAuthError extends Error {
    constructor(message) {
      super(message);
      this.name = "RailwayAuthError";
    }
  }
  const RECONNECT_MESSAGE =
    "Your Railway login has expired. Reconnect this connector " +
    "(in Claude: Settings → Connectors → reconnect; in ChatGPT: re-authorize " +
    "the connector) and try again.";

  async function gqlRequest(query, variables) {
    try {
      return await railwayClient.request(query, variables);
    } catch (err) {
      // Static-token deployments can't refresh; a stale override is a config
      // problem for the operator, not something the end user can reconnect.
      if (!isNotAuthorized(err) || RAILWAY_API_TOKEN || !mcpToken) throw err;
      const fresh = await forceRailwayRefresh(mcpToken);
      if (!fresh) throw new RailwayAuthError(RECONNECT_MESSAGE);
      currentRailwayToken = fresh;
      railwayClient = new GraphQLClient(
        "https://backboard.railway.com/graphql/v2",
        {
          headers: {
            Authorization: `Bearer ${currentRailwayToken}`,
            "x-source": "railway-mcp-server-remote",
          },
        }
      );
      return await railwayClient.request(query, variables);
    }
  }

  // Resolve an environment ID for a project: return it as-is if given,
  // otherwise the "production" environment, falling back to the first one.
  async function resolveEnvironmentId(projectId, environmentId) {
    if (environmentId) return environmentId;

    const data = await gqlRequest(
      gql`
        query ($id: String!) {
          project(id: $id) {
            environments {
              edges {
                node {
                  id
                  name
                }
              }
            }
          }
        }
      `,
      { id: projectId }
    );

    const envs = data.project?.environments?.edges?.map((e) => e.node) || [];
    if (envs.length === 0) {
      throw new Error(`No environments found for project ${projectId}`);
    }
    const prod = envs.find((e) => e.name === "production");
    return (prod ?? envs[0]).id;
  }

  // -- railway-list-workspaces --
  server.tool(
    "railway-list-workspaces",
    "List the Railway workspaces this connector can access (the ones you granted at login). Use a workspace id with railway-list-projects or railway-create-project.",
    {},
    async () => {
      try {
        const d = await gqlRequest(gql`
          query {
            me {
              workspaces {
                id
                name
              }
            }
          }
        `);
        const ws = d.me?.workspaces || [];
        if (ws.length === 0) {
          return toolResponse(
            "No accessible workspaces. Reconnect and grant a workspace when prompted."
          );
        }
        return toolResponse(
          `Workspaces you've granted access to:\n\n` +
            ws.map((w) => `- **${w.name}** (${w.id})`).join("\n")
        );
      } catch (error) {
        return toolError("Failed to list workspaces", error);
      }
    }
  );

  // -- railway-list-projects --
  server.tool(
    "railway-list-projects",
    "List Railway projects. Login-with-Railway scopes this connector to the workspaces you granted, so projects are listed per workspace. Pass workspaceId (from railway-list-workspaces) to scope to one.",
    {
      workspaceId: z
        .string()
        .optional()
        .describe("Limit to a single workspace id (from railway-list-workspaces)."),
    },
    async ({ workspaceId }) => {
      try {
        let workspaces;
        if (workspaceId) {
          workspaces = [{ id: workspaceId, name: workspaceId }];
        } else {
          const wd = await gqlRequest(gql`
            query {
              me {
                workspaces {
                  id
                  name
                }
              }
            }
          `);
          workspaces = wd.me?.workspaces || [];
        }
        if (workspaces.length === 0) {
          return toolResponse(
            "No accessible workspaces. Reconnect and grant a workspace when prompted."
          );
        }

        const blocks = [];
        for (const w of workspaces) {
          const pd = await gqlRequest(
            gql`
              query ($w: String!) {
                projects(workspaceId: $w) {
                  edges {
                    node {
                      id
                      name
                    }
                  }
                }
              }
            `,
            { w: w.id }
          );
          const projs = pd.projects?.edges?.map((e) => e.node) || [];
          const lines = projs.length
            ? projs.map((p) => `  - ${p.name} (${p.id})`).join("\n")
            : "  (no projects)";
          blocks.push(`**${w.name}** (${w.id})\n${lines}`);
        }
        return toolResponse(blocks.join("\n\n"));
      } catch (error) {
        return toolError("Failed to list projects", error);
      }
    }
  );

  // -- railway-create-project --
  server.tool(
    "railway-create-project",
    "Create a new Railway project. With Login-with-Railway auth, pass workspaceId (from railway-list-workspaces) so it lands in a workspace you can access.",
    {
      name: z.string().describe("Name for the new project"),
      workspaceId: z
        .string()
        .optional()
        .describe(
          "Workspace id to create the project in (from railway-list-workspaces)."
        ),
    },
    async ({ name, workspaceId }) => {
      try {
        const data = await gqlRequest(
          gql`
            mutation ProjectCreate($input: ProjectCreateInput!) {
              projectCreate(input: $input) {
                id
                name
                environments {
                  edges {
                    node {
                      id
                      name
                    }
                  }
                }
              }
            }
          `,
          { input: { name, ...(workspaceId ? { workspaceId } : {}) } }
        );

        const project = data.projectCreate;
        const envs = project.environments?.edges?.map((e) => e.node) || [];
        const envLines = envs
          .map((e) => `  - ${e.name} (${e.id})`)
          .join("\n");

        return toolResponse(
          `Project created successfully!\n\n` +
            `**${project.name}** (ID: ${project.id})\n\n` +
            `Environments:\n${envLines || "  none"}`
        );
      } catch (error) {
        return toolError("Failed to create project", error);
      }
    }
  );

  // -- railway-get-project --
  server.tool(
    "railway-get-project",
    "Get details of a specific Railway project",
    { projectId: z.string().describe("The project ID") },
    async ({ projectId }) => {
      try {
        const data = await gqlRequest(
          gql`
            query ($id: String!) {
              project(id: $id) {
                id
                name
                description
                createdAt
                updatedAt
                environments {
                  edges {
                    node {
                      id
                      name
                    }
                  }
                }
                services {
                  edges {
                    node {
                      id
                      name
                      icon
                    }
                  }
                }
              }
            }
          `,
          { id: projectId }
        );

        const p = data.project;
        const envs = p.environments?.edges?.map((e) => `  - ${e.node.name} (${e.node.id})`).join("\n") || "  none";
        const svcs = p.services?.edges?.map((e) => `  - ${e.node.name} (${e.node.id})`).join("\n") || "  none";

        return toolResponse(
          `**${p.name}** (${p.id})\n` +
            `Description: ${p.description || "none"}\n` +
            `Created: ${new Date(p.createdAt).toLocaleDateString()}\n\n` +
            `Environments:\n${envs}\n\n` +
            `Services:\n${svcs}`
        );
      } catch (error) {
        return toolError("Failed to get project", error);
      }
    }
  );

  // -- railway-list-services --
  server.tool(
    "railway-list-services",
    "List all services in a Railway project",
    { projectId: z.string().describe("The project ID") },
    async ({ projectId }) => {
      try {
        const data = await gqlRequest(
          gql`
            query ($id: String!) {
              project(id: $id) {
                services {
                  edges {
                    node {
                      id
                      name
                      icon
                      updatedAt
                      serviceInstances {
                        edges {
                          node {
                            source {
                              repo
                              image
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          `,
          { id: projectId }
        );

        const services = data.project.services?.edges?.map((e) => e.node) || [];
        if (services.length === 0) {
          return toolResponse("No services found in this project.");
        }

        const sourceOf = (s) => {
          const src = s.serviceInstances?.edges?.[0]?.node?.source;
          if (!src) return null;
          if (src.repo) return `repo: ${src.repo}`;
          if (src.image) return `image: ${src.image}`;
          return null;
        };

        const formatted = services
          .map((s) => {
            const src = sourceOf(s);
            return `- **${s.name}** (ID: ${s.id})${
              src ? `\n    ${src}` : `\n    no source connected yet`
            }`;
          })
          .join("\n");

        return toolResponse(
          `Found ${services.length} service(s):\n\n${formatted}`
        );
      } catch (error) {
        return toolError("Failed to list services", error);
      }
    }
  );

  // -- railway-list-variables --
  server.tool(
    "railway-list-variables",
    "List environment variables for a service. Values are MASKED by default so secrets don't leak into the conversation; only the variable names and value lengths are shown. Pass reveal=true to return raw values (use sparingly, and never for a service you don't own). environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID"),
      reveal: z
        .boolean()
        .optional()
        .describe(
          "Return raw, unmasked values. WARNING: this prints secret values (API keys, DB URLs) into the chat transcript. Defaults to false."
        ),
    },
    async ({ projectId, environmentId, serviceId, reveal }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const data = await gqlRequest(
          gql`
            query ($projectId: String!, $environmentId: String!, $serviceId: String!) {
              variables(
                projectId: $projectId
                environmentId: $environmentId
                serviceId: $serviceId
              )
            }
          `,
          { projectId, environmentId: envId, serviceId }
        );

        const vars = data.variables || {};
        const entries = Object.entries(vars);

        if (entries.length === 0) {
          return toolResponse("No variables found.");
        }

        const formatted = entries
          .map(
            ([key, value]) =>
              `- **${key}** = \`${reveal ? value : maskValue(value)}\``
          )
          .join("\n");

        const note = reveal
          ? ""
          : "\n\n_Values are masked. Call again with `reveal: true` to see raw values (this exposes secrets in the chat)._";

        return toolResponse(
          `Found ${entries.length} variable(s):\n\n${formatted}${note}`
        );
      } catch (error) {
        return toolError("Failed to list variables", error);
      }
    }
  );

  // -- railway-set-variables --
  server.tool(
    "railway-set-variables",
    "Set environment variables for a service. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID"),
      variables: z
        .record(z.string())
        .describe("Key-value pairs of variables to set"),
    },
    async ({ projectId, environmentId, serviceId, variables }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        await gqlRequest(
          gql`
            mutation ($input: VariableCollectionUpsertInput!) {
              variableCollectionUpsert(input: $input)
            }
          `,
          {
            input: {
              projectId,
              environmentId: envId,
              serviceId,
              variables,
            },
          }
        );

        const keys = Object.keys(variables);
        return toolResponse(
          `Successfully set ${keys.length} variable(s): ${keys.join(", ")}`
        );
      } catch (error) {
        return toolError("Failed to set variables", error);
      }
    }
  );

  // -- railway-get-logs --
  server.tool(
    "railway-get-logs",
    "Get deployment logs for a service. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID"),
      limit: z.coerce.number().int().optional().describe("Number of log lines (default 100)"),
    },
    async ({ projectId, environmentId, serviceId, limit }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const deployData = await gqlRequest(
          gql`
            query ($projectId: String!, $environmentId: String!, $serviceId: String!) {
              deployments(
                first: 1
                input: {
                  projectId: $projectId
                  environmentId: $environmentId
                  serviceId: $serviceId
                }
              ) {
                edges {
                  node {
                    id
                    status
                    createdAt
                  }
                }
              }
            }
          `,
          { projectId, environmentId: envId, serviceId }
        );

        const deployment = deployData.deployments?.edges?.[0]?.node;
        if (!deployment) {
          return toolResponse("No deployments found for this service.");
        }

        const logData = await gqlRequest(
          gql`
            query ($deploymentId: String!, $limit: Int) {
              deploymentLogs(deploymentId: $deploymentId, limit: $limit) {
                message
                timestamp
                severity
              }
            }
          `,
          { deploymentId: deployment.id, limit: limit || 100 }
        );

        const logs = logData.deploymentLogs || [];
        if (logs.length === 0) {
          return toolResponse(
            `Deployment ${deployment.id} (${deployment.status}) has no logs yet.`
          );
        }

        const formatted = logs
          .map(
            (l) =>
              `[${new Date(l.timestamp).toISOString()}] ${l.severity || "INFO"}: ${l.message}`
          )
          .join("\n");

        return toolResponse(
          `Logs for deployment ${deployment.id} (${deployment.status}):\n\n${formatted}`
        );
      } catch (error) {
        return toolError("Failed to get logs", error);
      }
    }
  );

  // -- railway-list-deployments --
  server.tool(
    "railway-list-deployments",
    "List recent deployments for a service. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID"),
      limit: z
        .coerce.number().int()
        .optional()
        .describe("Number of deployments to show (default 10)"),
    },
    async ({ projectId, environmentId, serviceId, limit }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const data = await gqlRequest(
          gql`
            query (
              $projectId: String!
              $environmentId: String!
              $serviceId: String!
              $limit: Int
            ) {
              deployments(
                first: $limit
                input: {
                  projectId: $projectId
                  environmentId: $environmentId
                  serviceId: $serviceId
                }
              ) {
                edges {
                  node {
                    id
                    status
                    createdAt
                    updatedAt
                    meta
                  }
                }
              }
            }
          `,
          { projectId, environmentId: envId, serviceId, limit: limit || 10 }
        );

        const deployments =
          data.deployments?.edges?.map((e) => e.node) || [];
        if (deployments.length === 0) {
          return toolResponse("No deployments found.");
        }

        const formatted = deployments
          .map(
            (d) =>
              `- **${d.status}** (${d.id})\n  Created: ${new Date(d.createdAt).toISOString()}`
          )
          .join("\n");

        return toolResponse(
          `Found ${deployments.length} deployment(s):\n\n${formatted}`
        );
      } catch (error) {
        return toolError("Failed to list deployments", error);
      }
    }
  );

  // -- railway-generate-domain --
  server.tool(
    "railway-generate-domain",
    "Generate a Railway domain for a service. environmentId defaults to the project's production environment. targetPort is optional — Railway will auto-detect from the running service if omitted.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID"),
      targetPort: z
        .coerce.number().int()
        .optional()
        .describe(
          "Port your app listens on. Optional — Railway auto-detects from the running service if omitted."
        ),
    },
    async ({ projectId, environmentId, serviceId, targetPort }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);

        const input = { serviceId, environmentId: envId };
        if (targetPort !== undefined) {
          input.targetPort = targetPort;
        }

        const data = await gqlRequest(
          gql`
            mutation ($input: ServiceDomainCreateInput!) {
              serviceDomainCreate(input: $input) {
                id
                domain
              }
            }
          `,
          { input }
        );

        const domain = data.serviceDomainCreate?.domain;
        return toolResponse(
          `Domain generated: **${domain}**\n\nYour service will be available at https://${domain}`
        );
      } catch (error) {
        return toolError("Failed to generate domain", error);
      }
    }
  );

  // -- railway-create-environment --
  server.tool(
    "railway-create-environment",
    "Create a new environment in a Railway project",
    {
      projectId: z.string().describe("The project ID"),
      name: z.string().describe("Name for the new environment"),
    },
    async ({ projectId, name }) => {
      try {
        const data = await gqlRequest(
          gql`
            mutation ($input: EnvironmentCreateInput!) {
              environmentCreate(input: $input) {
                id
                name
              }
            }
          `,
          {
            input: {
              projectId,
              name,
            },
          }
        );

        const env = data.environmentCreate;
        return toolResponse(
          `Environment created: **${env.name}** (ID: ${env.id})`
        );
      } catch (error) {
        return toolError("Failed to create environment", error);
      }
    }
  );

  // -- railway-deploy-template --
  server.tool(
    "railway-deploy-template",
    "Search for and deploy a Railway template (e.g., databases, apps). When projectId is provided, environmentId defaults to the project's production environment.",
    {
      searchQuery: z
        .string()
        .optional()
        .describe("Search query to find templates"),
      templateId: z
        .string()
        .optional()
        .describe("Template ID to deploy (if known)"),
      projectId: z
        .string()
        .optional()
        .describe("Project ID to deploy into (creates new if not specified)"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "Environment ID to deploy into (defaults to project's production environment when projectId is provided)"
        ),
    },
    async ({ searchQuery, templateId, projectId, environmentId }) => {
      try {
        if (!templateId) {
          const data = await gqlRequest(gql`
            query {
              templates {
                edges {
                  node {
                    id
                    name
                    description
                    category
                    activeProjects
                    isVerified
                  }
                }
              }
            }
          `);

          let templates = data.templates.edges.map((e) => e.node);

          if (searchQuery) {
            const query = searchQuery.toLowerCase();
            templates = templates.filter(
              (t) =>
                t.name.toLowerCase().includes(query) ||
                t.description?.toLowerCase().includes(query) ||
                t.category?.toLowerCase().includes(query)
            );
          }

          templates.sort((a, b) => {
            if (a.isVerified && !b.isVerified) return -1;
            if (!a.isVerified && b.isVerified) return 1;
            return (b.activeProjects || 0) - (a.activeProjects || 0);
          });

          const top = templates.slice(0, 15);
          const formatted = top
            .map(
              (t) =>
                `- **${t.name}** (ID: ${t.id})${t.isVerified ? " ✓" : ""}\n  ${t.description || "No description"}\n  Category: ${t.category || "N/A"} | Active: ${t.activeProjects || 0}`
            )
            .join("\n");

          return toolResponse(
            `Found ${templates.length} template(s)${searchQuery ? ` matching "${searchQuery}"` : ""}:\n\n${formatted}\n\nTo deploy, call this tool again with the templateId.`
          );
        }

        const templateData = await gqlRequest(
          gql`
            query ($id: String!) {
              template(id: $id) {
                id
                name
                serializedConfig
              }
            }
          `,
          { id: templateId }
        );

        const template = templateData.template;
        if (!template) {
          return toolResponse(`Template not found: ${templateId}`);
        }

        const serializedConfig =
          typeof template.serializedConfig === "string"
            ? JSON.parse(template.serializedConfig)
            : template.serializedConfig;

        let envId = environmentId;
        if (projectId && !envId) {
          envId = await resolveEnvironmentId(projectId, undefined);
        }

        const deployResult = await gqlRequest(
          gql`
            mutation (
              $environmentId: String
              $projectId: String
              $templateId: String!
              $serializedConfig: SerializedTemplateConfig!
            ) {
              templateDeployV2(
                input: {
                  environmentId: $environmentId
                  projectId: $projectId
                  templateId: $templateId
                  serializedConfig: $serializedConfig
                }
              ) {
                projectId
                workflowId
              }
            }
          `,
          {
            environmentId: envId,
            projectId,
            templateId,
            serializedConfig,
          }
        );

        const result = deployResult.templateDeployV2;
        return toolResponse(
          `Template **${template.name}** deployed!\n\n` +
            `Project ID: ${result.projectId}\n` +
            `Workflow ID: ${result.workflowId}\n\n` +
            `Check the Railway dashboard for deployment progress.`
        );
      } catch (error) {
        return toolError("Failed to deploy template", error);
      }
    }
  );

  // -- railway-status --
  server.tool(
    "railway-status",
    "Check Railway platform status and API connectivity",
    {},
    async () => {
      try {
        const data = await gqlRequest(gql`
          query {
            me {
              id
              name
              email
            }
          }
        `);

        return toolResponse(
          `Railway API is connected.\n\n` +
            `Authenticated as: **${data.me.name}** (${data.me.email})\n` +
            `User ID: ${data.me.id}`
        );
      } catch (error) {
        return toolResponse(
          `Railway API connection failed: ${error.message}\n\n` +
            `Check that RAILWAY_API_TOKEN is valid.`
        );
      }
    }
  );

  // -- railway-redeploy-service --
  server.tool(
    "railway-redeploy-service",
    "Trigger a redeployment of a service using the latest deployment. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID"),
    },
    async ({ projectId, environmentId, serviceId }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const deployData = await gqlRequest(
          gql`
            query ($projectId: String!, $environmentId: String!, $serviceId: String!) {
              deployments(
                first: 1
                input: {
                  projectId: $projectId
                  environmentId: $environmentId
                  serviceId: $serviceId
                }
              ) {
                edges {
                  node {
                    id
                  }
                }
              }
            }
          `,
          { projectId, environmentId: envId, serviceId }
        );

        const latestDeployment = deployData.deployments?.edges?.[0]?.node;
        if (!latestDeployment) {
          // No prior deployment — common when a service was created and connected
          // to a repo but the first build never ran. Trigger a fresh deploy from
          // the connected source's latest commit instead of giving up.
          try {
            await gqlRequest(
              gql`
                mutation ($serviceId: String!, $environmentId: String!) {
                  serviceInstanceDeploy(
                    serviceId: $serviceId
                    environmentId: $environmentId
                    latestCommit: true
                  )
                }
              `,
              { serviceId, environmentId: envId }
            );
            return toolResponse(
              `No prior deployment existed, so I kicked off a fresh deploy from the connected source's latest commit. ` +
                `Use railway-list-deployments to watch the build.\n\n` +
                `If the build can't fetch the repo, either no repo is connected to this service yet ` +
                `(recreate it with railway-create-service-from-github), or Railway's GitHub App lacks access to a private repo ` +
                `(authorize it at ${RAILWAY_GITHUB_APP_URL}, or make the repo public — call railway-github-access for the walkthrough).`
            );
          } catch (freshErr) {
            return toolResponse(
              `No prior deployment to redeploy, and a fresh deploy couldn't start:\n${freshErr.message}\n\n` +
                `Most likely this service has no GitHub repo connected yet — recreate it with railway-create-service-from-github ` +
                `(after confirming Railway's GitHub App can access the repo for private repos).`
            );
          }
        }

        await gqlRequest(
          gql`
            mutation ($id: String!) {
              deploymentRedeploy(id: $id) {
                id
                status
              }
            }
          `,
          { id: latestDeployment.id }
        );

        return toolResponse(
          `Redeployment triggered for service. Check the dashboard for progress.`
        );
      } catch (error) {
        return toolError("Failed to redeploy", error);
      }
    }
  );

  // -- railway-create-service-from-github --
  server.tool(
    "railway-create-service-from-github",
    "Create a new service from a GitHub repository and trigger initial deployment. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID to deploy to (defaults to the project's production environment)"
        ),
      repo: z
        .string()
        .describe("GitHub repository in owner/name format (e.g., samaybar/hello-nextjs)"),
      name: z.string().optional().describe("Service name (defaults to repo name)"),
      branch: z
        .string()
        .optional()
        .describe("Branch to deploy (default: main)"),
    },
    async ({ projectId, environmentId, repo, name, branch }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);

        const createInput = {
          projectId,
          source: { repo },
        };
        if (name) createInput.name = name;

        const createData = await gqlRequest(
          gql`
            mutation ServiceCreate($input: ServiceCreateInput!) {
              serviceCreate(input: $input) {
                id
                name
              }
            }
          `,
          { input: createInput }
        );

        const service = createData.serviceCreate;

        try {
          await gqlRequest(
            gql`
              mutation ServiceConnect($id: String!, $input: ServiceConnectInput!) {
                serviceConnect(id: $id, input: $input) {
                  id
                }
              }
            `,
            {
              id: service.id,
              input: {
                repo,
                branch: branch || "main",
              },
            }
          );
        } catch (connectError) {
          const msg = connectError.message || "";
          // Auto-clean the orphan shell: the service exists but has no working
          // source, so leaving it just litters the project with empty services.
          let cleaned = false;
          try {
            await gqlRequest(
              gql`
                mutation ServiceDelete($id: String!) {
                  serviceDelete(id: $id)
                }
              `,
              { id: service.id }
            );
            cleaned = true;
          } catch {
            // Cleanup is best-effort; if it fails we tell the user the shell remains.
          }
          const shellNote = cleaned
            ? `I removed the empty service I'd just created, so nothing is left dangling in your project.`
            : `An empty service shell (ID: ${service.id}) was left behind and couldn't be auto-removed — delete it with railway-delete-service.`;

          if (/does not have access|access to the repo|not have access/i.test(msg)) {
            return toolResponse(
              `Railway couldn't connect the repo **${repo}**:\n\n` +
                `> ${msg}\n\n` +
                `This is the separate-GitHub-App gap. The repo was created through your connector's GitHub App, but **Railway's own GitHub App** hasn't been granted access to it, and Railway can only deploy from repos its App can see (private repos in particular require an explicit grant).\n\n` +
                `**One-click fix:** install/authorize Railway's GitHub App here → ${RAILWAY_GITHUB_APP_URL}\n` +
                `On that screen, under *Repository access* choose **All repositories** (recommended if you build from Claude often, so every new repo just works) or *Only select repositories* and add **${repo}**, then Install & Authorize.\n\n` +
                `**Or make the repo public** (ask me and I'll flip it) — that skips the App-access requirement entirely.\n\n` +
                `(Want the full walkthrough? Call railway-github-access.)\n\n` +
                `${shellNote}\n\n` +
                `Once access is sorted, just ask me to deploy ${repo} again and I'll recreate the service cleanly.`
            );
          }
          return toolResponse(
            `Connecting the repo **${repo}** failed:\n${msg}\n\n${shellNote}`
          );
        }

        try {
          await gqlRequest(
            gql`
              mutation ServiceInstanceDeploy($serviceId: String!, $environmentId: String!) {
                serviceInstanceDeploy(serviceId: $serviceId, environmentId: $environmentId)
              }
            `,
            { serviceId: service.id, environmentId: envId }
          );
        } catch (deployError) {
          return toolResponse(
            `Service created and connected, but deployment trigger failed.\n\n` +
              `**${service.name}** (ID: ${service.id})\n` +
              `Repository: ${repo}\n` +
              `Error: ${deployError.message}\n\n` +
              `Try using railway-redeploy-service to manually trigger deployment.`
          );
        }

        return toolResponse(
          `Service created and deployment triggered!\n\n` +
            `**${service.name}** (ID: ${service.id})\n` +
            `Repository: ${repo} (branch: ${branch || "main"})\n` +
            `Environment: ${envId}\n\n` +
            `Use railway-list-deployments to check build progress.`
        );
      } catch (error) {
        return toolError("Failed to create service", error);
      }
    }
  );

  // -- railway-delete-service --
  server.tool(
    "railway-delete-service",
    "Delete a service from a project",
    {
      serviceId: z.string().describe("The service ID to delete"),
    },
    async ({ serviceId }) => {
      try {
        await gqlRequest(
          gql`
            mutation ServiceDelete($id: String!) {
              serviceDelete(id: $id)
            }
          `,
          { id: serviceId }
        );

        return toolResponse(`Service ${serviceId} deleted successfully.`);
      } catch (error) {
        return toolError("Failed to delete service", error);
      }
    }
  );

  // -- railway-query-postgres --
  server.tool(
    "railway-query-postgres",
    "Execute a SQL query against a PostgreSQL database",
    {
      connectionString: z
        .string()
        .describe(
          "PostgreSQL connection string (e.g., postgresql://user:pass@host:port/db)"
        ),
      sql: z.string().describe("SQL query to execute"),
    },
    async ({ connectionString, sql }) => {
      const client = new pg.Client({ connectionString });
      try {
        await client.connect();
        const result = await client.query(sql);
        await client.end();

        return toolResponse(
          `Query executed successfully.\n\n` +
            `Rows returned: ${result.rowCount}\n\n` +
            `Results:\n\`\`\`json\n${JSON.stringify(result.rows, null, 2)}\n\`\`\``
        );
      } catch (error) {
        try {
          await client.end();
        } catch {
          // Ignore cleanup errors
        }
        return toolResponse(`Query failed: ${error.message}`);
      }
    }
  );

  // -- update-this-connector (self-redeploy to the latest version) --
  server.tool(
    "update-this-connector",
    "Redeploy THIS MCP connector from the latest published version (pulls the newest code from its source repo). Use when the user asks to update the connector. Settings and the GitHub connection persist across the update.",
    {},
    async () => {
      const serviceId = process.env.RAILWAY_SERVICE_ID;
      const environmentId = process.env.RAILWAY_ENVIRONMENT_ID;
      if (!serviceId || !environmentId) {
        return toolResponse(
          "Can't self-identify this service (RAILWAY_SERVICE_ID / RAILWAY_ENVIRONMENT_ID aren't set). This tool only works on a Railway deployment."
        );
      }
      try {
        await gqlRequest(
          gql`
            mutation ($serviceId: String!, $environmentId: String!) {
              serviceInstanceDeploy(
                serviceId: $serviceId
                environmentId: $environmentId
                latestCommit: true
              )
            }
          `,
          { serviceId, environmentId }
        );
        return toolResponse(
          "Updating this connector to the latest version — it'll redeploy in ~1-2 minutes. Your GitHub connection and settings persist. If the available tools change, reconnect the connector in Claude afterward."
        );
      } catch (error) {
        return toolError("Failed to update the connector", error);
      }
    }
  );

  // -- railway-github-access --
  // Tells the user exactly how to let Railway deploy from their (private) repos by
  // installing/authorizing Railway's first-party GitHub App. Call this whenever a
  // deploy fails with "User does not have access to the repo", or when the user asks
  // how to connect GitHub to Railway. Not in TOOL_GROUP → always available.
  server.tool(
    "railway-github-access",
    "Explain how to install/authorize Railway's GitHub App so Railway can deploy the user's repos (especially private ones). Returns the direct one-click setup link and step-by-step instructions. Use this when a deploy fails because Railway can't access a repo, or when the user asks how to give Railway access to GitHub.",
    {
      repo: z
        .string()
        .optional()
        .describe("Optional owner/name of the specific repo to grant access to, for tailored wording"),
    },
    async ({ repo }) => {
      const target = repo ? `**${repo}**` : "your repo";
      return toolResponse(
        `To let Railway deploy ${target}, Railway's own GitHub App needs access to it. This is a one-time, browser-based step (GitHub requires you to approve it yourself — it can't be done via the API).\n\n` +
          `**One-click setup:** ${RAILWAY_GITHUB_APP_URL}\n\n` +
          `On that screen:\n` +
          `1. Pick the account/org that owns the repo${repo ? ` (${repo.split("/")[0]})` : ""}.\n` +
          `2. Under **Repository access**, choose either:\n` +
          `   - **All repositories** — recommended if you build from Claude often, so every repo you create here just works with no extra steps, or\n` +
          `   - **Only select repositories** and add ${repo ? `**${repo}**` : "the repo you want to deploy"}.\n` +
          `3. Click **Install & Authorize** (or **Save** if Railway's App is already installed).\n\n` +
          `That's it — come back and ask me to deploy again.\n\n` +
          `**Don't want to grant access?** Make the repo **public** instead (ask me and I'll switch it) — public repos deploy without the App needing per-repo access.`
      );
    }
  );

  // -- volume tools (railway-create-volume, railway-list-volumes, railway-delete-volume) --
  registerVolumeTools(server, { gqlRequest, resolveEnvironmentId });

  // -- GitHub connection (device flow) — these are always available so the
  //    user can connect; the action tools below appear once connected. --
  // When GitHub isn't connected, octokit is a proxy that throws a friendly
  // error on use — so the GitHub tools can stay listed (stable tool list)
  // and just tell the user to run github-connect.
  const octokit = githubToken
    ? new Octokit({ auth: githubToken })
    : new Proxy(
        {},
        {
          get() {
            throw new Error("GitHub isn't connected yet — run github-connect first.");
          },
        }
      );

  server.tool(
    "github-connect",
    "Connect your GitHub account so the GitHub tools work. Returns an install link (to choose which repos the agent can touch) and a one-time code to authorize at github.com/login/device.",
    {},
    async () => {
      try {
        const d = await githubDeviceStart();
        startGitHubDevicePoll(d);
        const installUrl = `https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`;
        const mins = Math.round((d.expires_in || 900) / 60);
        return toolResponse(
          `**Connect GitHub — two quick steps:**\n\n` +
            `1. **Install the app & pick repos:** ${installUrl}\n` +
            `2. **Authorize:** open ${d.verification_uri} and enter code **${d.user_code}**\n\n` +
            `I'll detect it automatically (within ~${mins} min). Run **github-status** to confirm. ` +
            `Once connected, the GitHub tools activate — you may need to reconnect this connector in Claude for them to appear.`
        );
      } catch (e) {
        return toolResponse(`Failed to start GitHub connect: ${e.message}`);
      }
    }
  );

  server.tool(
    "github-status",
    "Check whether GitHub is connected, and as which account.",
    {},
    async () => {
      const t = await resolveGitHubToken();
      if (!t) return toolResponse("GitHub is not connected. Run github-connect to connect.");
      try {
        const me = await new Octokit({ auth: t }).users.getAuthenticated();
        return toolResponse(`GitHub connected as **${me.data.login}**. The GitHub tools are active.`);
      } catch (e) {
        return toolResponse(
          `A GitHub token is set but the check failed (${e.message}). It may be expired, or the app may need to be installed on your repos.`
        );
      }
    }
  );

  // -- GitHub action tools (always listed; they error helpfully until github-connect) --
  {
  // -- github-check-connection --
  server.tool(
    "github-check-connection",
    "Check GitHub API connectivity and show authenticated user",
    {},
    async () => {
      try {
        const { data: user } = await octokit.users.getAuthenticated();
        return toolResponse(
          `GitHub API connected.\n\n` +
            `Authenticated as: **${user.login}** (${user.name || "no name"})\n` +
            `Profile: ${user.html_url}`
        );
      } catch (error) {
        return toolResponse(`GitHub API connection failed: ${error.message}`);
      }
    }
  );

  // -- github-list-repos --
  server.tool(
    "github-list-repos",
    "List repositories accessible to the authenticated user",
    {
      type: z
        .enum(["all", "owner", "public", "private", "member"])
        .optional()
        .describe("Filter by repo type (default: all)"),
      sort: z
        .enum(["created", "updated", "pushed", "full_name"])
        .optional()
        .describe("Sort field (default: updated)"),
      limit: z.number().optional().describe("Max repos to return (default: 30)"),
    },
    async ({ type, sort, limit }) => {
      try {
        const { data: repos } = await octokit.repos.listForAuthenticatedUser({
          type: type || "all",
          sort: sort || "updated",
          per_page: limit || 30,
        });

        if (repos.length === 0) {
          return toolResponse("No repositories found.");
        }

        const formatted = repos
          .map(
            (r) =>
              `- **${r.full_name}**${r.private ? " (private)" : ""}\n` +
              `  ${r.description || "No description"}\n` +
              `  Updated: ${new Date(r.updated_at).toLocaleDateString()}`
          )
          .join("\n");

        return toolResponse(`Found ${repos.length} repository(s):\n\n${formatted}`);
      } catch (error) {
        return toolError("Failed to list repos", error);
      }
    }
  );

  // -- github-get-repo --
  server.tool(
    "github-get-repo",
    "Get details about a specific repository",
    {
      owner: z.string().describe("Repository owner (username or org)"),
      repo: z.string().describe("Repository name"),
    },
    async ({ owner, repo }) => {
      try {
        const { data: r } = await octokit.repos.get({ owner, repo });

        return toolResponse(
          `**${r.full_name}**${r.private ? " (private)" : " (public)"}\n\n` +
            `Description: ${r.description || "None"}\n` +
            `Default branch: ${r.default_branch}\n` +
            `Language: ${r.language || "N/A"}\n` +
            `Stars: ${r.stargazers_count} | Forks: ${r.forks_count}\n` +
            `Created: ${new Date(r.created_at).toLocaleDateString()}\n` +
            `Updated: ${new Date(r.updated_at).toLocaleDateString()}\n` +
            `URL: ${r.html_url}`
        );
      } catch (error) {
        return toolError("Failed to get repo", error);
      }
    }
  );

  // -- github-create-repo --
  server.tool(
    "github-create-repo",
    "Create a new GitHub repository. Defaults to PRIVATE (safer — keeps code and any accidentally-committed secrets out of public view, which a new user may not realize). If the user hasn't specified, create it private and mention they can make it public if they prefer.",
    {
      name: z.string().describe("Repository name"),
      description: z.string().optional().describe("Repository description"),
      private: z
        .boolean()
        .optional()
        .describe("Make repository private. Default true. Only set false if the user explicitly wants a public repo."),
      owner: z.string().optional().describe("Org to create repo in (defaults to authenticated user)"),
    },
    async ({ name, description, private: isPrivate = true, owner }) => {
      try {
        let data;
        if (owner) {
          // Check if owner is an org or the authenticated user
          const { data: user } = await octokit.users.getAuthenticated();
          if (owner !== user.login) {
            ({ data } = await octokit.repos.createInOrg({
              org: owner,
              name,
              description,
              private: isPrivate,
              auto_init: false,
            }));
          } else {
            ({ data } = await octokit.repos.createForAuthenticatedUser({
              name,
              description,
              private: isPrivate,
              auto_init: false,
            }));
          }
        } else {
          ({ data } = await octokit.repos.createForAuthenticatedUser({
            name,
            description,
            private: isPrivate,
            auto_init: false,
          }));
        }

        const privacyNote = data.private
          ? `\n\nIt's **private** by default — that keeps your code and any secrets out of public view. ` +
            `One heads-up: to deploy a private repo on Railway, Railway's GitHub App needs access to it ` +
            `(authorize Railway's GitHub App once at ${RAILWAY_GITHUB_APP_URL} — choose *All repositories* so future repos just work, or grant this one). ` +
            `Prefer it public instead? Just ask and I'll switch it.`
          : `\n\nIt's **public**.`;

        return toolResponse(
          `Repository created!\n\n` +
            `**${data.full_name}**${data.private ? " (private)" : " (public)"}\n` +
            `${data.description ? `Description: ${data.description}\n` : ""}` +
            `URL: ${data.html_url}\n` +
            `Clone: ${data.clone_url}` +
            privacyNote
        );
      } catch (error) {
        return toolError("Failed to create repo", error);
      }
    }
  );

  // -- github-list-branches --
  server.tool(
    "github-list-branches",
    "List branches in a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    async ({ owner, repo }) => {
      try {
        const { data: branches } = await octokit.repos.listBranches({
          owner,
          repo,
          per_page: 100,
        });

        if (branches.length === 0) {
          return toolResponse("No branches found.");
        }

        const formatted = branches
          .map((b) => `- ${b.name}${b.protected ? " (protected)" : ""}`)
          .join("\n");

        return toolResponse(`Found ${branches.length} branch(es):\n\n${formatted}`);
      } catch (error) {
        return toolError("Failed to list branches", error);
      }
    }
  );

  // -- github-create-branch --
  server.tool(
    "github-create-branch",
    "Create a new branch from an existing ref",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      branch: z.string().describe("Name for the new branch"),
      from: z
        .string()
        .optional()
        .describe("Source branch or SHA (default: default branch)"),
    },
    async ({ owner, repo, branch, from }) => {
      try {
        // Get the SHA to branch from
        let sha;
        if (from) {
          try {
            const { data: ref } = await octokit.git.getRef({
              owner,
              repo,
              ref: `heads/${from}`,
            });
            sha = ref.object.sha;
          } catch {
            // Maybe it's a SHA directly
            sha = from;
          }
        } else {
          const { data: repoData } = await octokit.repos.get({ owner, repo });
          const { data: ref } = await octokit.git.getRef({
            owner,
            repo,
            ref: `heads/${repoData.default_branch}`,
          });
          sha = ref.object.sha;
        }

        await octokit.git.createRef({
          owner,
          repo,
          ref: `refs/heads/${branch}`,
          sha,
        });

        return toolResponse(
          `Branch **${branch}** created successfully from ${from || "default branch"}.`
        );
      } catch (error) {
        return toolError("Failed to create branch", error);
      }
    }
  );

  // -- github-get-file --
  server.tool(
    "github-get-file",
    "Get the contents of a file from a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      path: z.string().describe("Path to the file"),
      ref: z.string().optional().describe("Branch, tag, or SHA (default: default branch)"),
    },
    async ({ owner, repo, path: filePath, ref }) => {
      try {
        const { data } = await octokit.repos.getContent({
          owner,
          repo,
          path: filePath,
          ref,
        });

        if (Array.isArray(data)) {
          return toolResponse(
            `Path is a directory with ${data.length} items:\n\n` +
              data.map((f) => `- ${f.type === "dir" ? "[dir] " : ""}${f.name}`).join("\n")
          );
        }

        if (data.type !== "file") {
          return toolResponse(`Path is a ${data.type}, not a file.`);
        }

        const content = Buffer.from(data.content, "base64").toString("utf-8");

        return toolResponse(
          `**${filePath}** (${data.size} bytes, SHA: ${data.sha})\n\n\`\`\`\n${content}\n\`\`\``
        );
      } catch (error) {
        return toolError("Failed to get file", error);
      }
    }
  );

  // -- github-create-or-update-file --
  server.tool(
    "github-create-or-update-file",
    "Create or update a file in a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      path: z.string().describe("Path to the file"),
      content: z.string().describe("File content"),
      message: z.string().describe("Commit message"),
      branch: z.string().optional().describe("Branch to commit to (default: default branch)"),
    },
    async ({ owner, repo, path: filePath, content, message, branch }) => {
      try {
        // Check if file exists to get its SHA
        let sha;
        try {
          const { data: existing } = await octokit.repos.getContent({
            owner,
            repo,
            path: filePath,
            ref: branch,
          });
          if (!Array.isArray(existing)) {
            sha = existing.sha;
          }
        } catch {
          // File doesn't exist, that's fine
        }

        const { data } = await octokit.repos.createOrUpdateFileContents({
          owner,
          repo,
          path: filePath,
          message,
          content: Buffer.from(content).toString("base64"),
          branch,
          sha,
        });

        const action = sha ? "Updated" : "Created";
        return toolResponse(
          `${action} **${filePath}**\n\n` +
            `Commit: ${data.commit.sha.slice(0, 7)} - ${data.commit.message}\n` +
            `URL: ${data.content?.html_url || data.commit.html_url}`
        );
      } catch (error) {
        return toolError("Failed to create/update file", error);
      }
    }
  );

  // -- github-patch-file --
  server.tool(
    "github-patch-file",
    "Edit a file by replacing an exact string, sending only the change instead of the whole file. " +
      "Fetches the current file server-side, replaces old_str with new_str (old_str must appear exactly once), " +
      "and commits. Use this for edits to existing files; use github-create-or-update-file for new files or full rewrites.",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      path: z.string().describe("Path to the file"),
      old_str: z.string().describe("Exact string to find. Must match the file's current content verbatim and appear exactly once."),
      new_str: z.string().describe("String to replace old_str with. Pass an empty string to delete old_str."),
      message: z.string().describe("Commit message"),
      branch: z.string().optional().describe("Branch to commit to (default: default branch)"),
    },
    async ({ owner, repo, path: filePath, old_str, new_str, message, branch }) => {
      try {
        // Fetch current file content + sha (server-side, with the server's token).
        let existing;
        try {
          const { data } = await octokit.repos.getContent({
            owner,
            repo,
            path: filePath,
            ref: branch,
          });
          existing = data;
        } catch {
          return toolResponse(`Failed to patch: file '${filePath}' not found.`);
        }

        if (Array.isArray(existing) || existing.type !== "file") {
          return toolResponse(`Failed to patch: '${filePath}' is not a file.`);
        }

        const original = Buffer.from(existing.content, "base64").toString("utf-8");

        // Assert old_str appears exactly once.
        const firstIdx = original.indexOf(old_str);
        if (firstIdx === -1) {
          return toolResponse(
            `Failed to patch: old_str not found in '${filePath}'. ` +
              `The file may have changed; re-fetch with github-get-file and retry.`
          );
        }
        if (original.indexOf(old_str, firstIdx + 1) !== -1) {
          const count = original.split(old_str).length - 1;
          return toolResponse(
            `Failed to patch: old_str appears ${count} times in '${filePath}', must be unique. ` +
              `Include more surrounding context to make it match exactly once.`
          );
        }

        const updated =
          original.slice(0, firstIdx) + new_str + original.slice(firstIdx + old_str.length);

        if (updated === original) {
          return toolResponse(`No change: old_str and new_str are identical.`);
        }

        const { data: commit } = await octokit.repos.createOrUpdateFileContents({
          owner,
          repo,
          path: filePath,
          message,
          content: Buffer.from(updated).toString("base64"),
          branch,
          sha: existing.sha, // optimistic concurrency: rejects if the file moved
        });

        const bytesDelta = Buffer.byteLength(updated) - Buffer.byteLength(original);
        const sign = bytesDelta >= 0 ? "+" : "";
        return toolResponse(
          `Patched **${filePath}** (${sign}${bytesDelta} bytes)\n\n` +
            `Commit: ${commit.commit.sha.slice(0, 7)} - ${commit.commit.message}\n` +
            `New SHA: ${commit.content?.sha || "?"}\n` +
            `URL: ${commit.content?.html_url || commit.commit.html_url}`
        );
      } catch (error) {
        // A 409 here means the sha moved between fetch and commit (concurrent write).
        if (error.status === 409) {
          return toolResponse(
            `Failed to patch: the file changed between read and write (sha conflict). Retry the patch.`
          );
        }
        return toolError("Failed to patch file", error);
      }
    }
  );

  // -- github-delete-file --
  server.tool(
    "github-delete-file",
    "Delete a file from a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      path: z.string().describe("Path to the file"),
      message: z.string().describe("Commit message"),
      branch: z.string().optional().describe("Branch to commit to"),
    },
    async ({ owner, repo, path: filePath, message, branch }) => {
      try {
        // Get file SHA
        const { data: existing } = await octokit.repos.getContent({
          owner,
          repo,
          path: filePath,
          ref: branch,
        });

        if (Array.isArray(existing)) {
          return toolResponse("Cannot delete a directory.");
        }

        const { data } = await octokit.repos.deleteFile({
          owner,
          repo,
          path: filePath,
          message,
          sha: existing.sha,
          branch,
        });

        return toolResponse(
          `Deleted **${filePath}**\n\n` +
            `Commit: ${data.commit.sha.slice(0, 7)} - ${data.commit.message}`
        );
      } catch (error) {
        return toolError("Failed to delete file", error);
      }
    }
  );

  // -- github-list-pull-requests --
  server.tool(
    "github-list-pull-requests",
    "List pull requests in a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      state: z
        .enum(["open", "closed", "all"])
        .optional()
        .describe("Filter by state (default: open)"),
      limit: z.number().optional().describe("Max PRs to return (default: 30)"),
    },
    async ({ owner, repo, state, limit }) => {
      try {
        const { data: prs } = await octokit.pulls.list({
          owner,
          repo,
          state: state || "open",
          per_page: limit || 30,
        });

        if (prs.length === 0) {
          return toolResponse(`No ${state || "open"} pull requests found.`);
        }

        const formatted = prs
          .map(
            (pr) =>
              `- **#${pr.number}** ${pr.title}\n` +
              `  ${pr.user?.login} | ${pr.state} | ${pr.head.ref} -> ${pr.base.ref}\n` +
              `  ${pr.html_url}`
          )
          .join("\n");

        return toolResponse(`Found ${prs.length} pull request(s):\n\n${formatted}`);
      } catch (error) {
        return toolError("Failed to list PRs", error);
      }
    }
  );

  // -- github-get-pull-request --
  server.tool(
    "github-get-pull-request",
    "Get details about a specific pull request",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      pull_number: z.number().describe("Pull request number"),
    },
    async ({ owner, repo, pull_number }) => {
      try {
        const { data: pr } = await octokit.pulls.get({
          owner,
          repo,
          pull_number,
        });

        return toolResponse(
          `**#${pr.number} ${pr.title}**\n\n` +
            `State: ${pr.state}${pr.merged ? " (merged)" : ""}\n` +
            `Author: ${pr.user?.login}\n` +
            `Branch: ${pr.head.ref} -> ${pr.base.ref}\n` +
            `Changed files: ${pr.changed_files} | +${pr.additions} -${pr.deletions}\n` +
            `Created: ${new Date(pr.created_at).toLocaleDateString()}\n` +
            `URL: ${pr.html_url}\n\n` +
            `**Description:**\n${pr.body || "No description"}`
        );
      } catch (error) {
        return toolError("Failed to get PR", error);
      }
    }
  );

  // -- github-create-pull-request --
  server.tool(
    "github-create-pull-request",
    "Create a new pull request",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      title: z.string().describe("PR title"),
      head: z.string().describe("Branch containing changes"),
      base: z.string().describe("Branch to merge into"),
      body: z.string().optional().describe("PR description"),
      draft: z.boolean().optional().describe("Create as draft PR"),
    },
    async ({ owner, repo, title, head, base, body, draft }) => {
      try {
        const { data: pr } = await octokit.pulls.create({
          owner,
          repo,
          title,
          head,
          base,
          body,
          draft,
        });

        return toolResponse(
          `Pull request created!\n\n` +
            `**#${pr.number} ${pr.title}**\n` +
            `${pr.head.ref} -> ${pr.base.ref}\n` +
            `URL: ${pr.html_url}`
        );
      } catch (error) {
        return toolError("Failed to create PR", error);
      }
    }
  );

  // -- github-search-code --
  server.tool(
    "github-search-code",
    "Search for code across GitHub repositories",
    {
      query: z.string().describe("Search query (can include qualifiers like repo:, language:, path:)"),
      limit: z.number().optional().describe("Max results (default: 30)"),
    },
    async ({ query, limit }) => {
      try {
        const { data } = await octokit.search.code({
          q: query,
          per_page: limit || 30,
        });

        if (data.total_count === 0) {
          return toolResponse("No code matches found.");
        }

        const formatted = data.items
          .map(
            (item) =>
              `- **${item.repository.full_name}** ${item.path}\n` +
              `  ${item.html_url}`
          )
          .join("\n");

        return toolResponse(
          `Found ${data.total_count} result(s) (showing ${data.items.length}):\n\n${formatted}`
        );
      } catch (error) {
        return toolResponse(`Search failed: ${error.message}`);
      }
    }
  );

  // -- github-list-commits --
  server.tool(
    "github-list-commits",
    "List commits in a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      sha: z.string().optional().describe("Branch or SHA to list commits from"),
      path: z.string().optional().describe("Only commits affecting this path"),
      limit: z.number().optional().describe("Max commits to return (default: 30)"),
    },
    async ({ owner, repo, sha, path: filePath, limit }) => {
      try {
        const { data: commits } = await octokit.repos.listCommits({
          owner,
          repo,
          sha,
          path: filePath,
          per_page: limit || 30,
        });

        if (commits.length === 0) {
          return toolResponse("No commits found.");
        }

        const formatted = commits
          .map(
            (c) =>
              `- **${c.sha.slice(0, 7)}** ${c.commit.message.split("\n")[0]}\n` +
              `  ${c.commit.author?.name} | ${new Date(c.commit.author?.date).toLocaleDateString()}`
          )
          .join("\n");

        return toolResponse(`Found ${commits.length} commit(s):\n\n${formatted}`);
      } catch (error) {
        return toolError("Failed to list commits", error);
      }
    }
  );

  // -- github-get-diff --
  server.tool(
    "github-get-diff",
    "Get the diff for a pull request or between commits",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
      pull_number: z.number().optional().describe("Pull request number"),
      base: z.string().optional().describe("Base commit SHA (if not using PR)"),
      head: z.string().optional().describe("Head commit SHA (if not using PR)"),
    },
    async ({ owner, repo, pull_number, base, head }) => {
      try {
        if (pull_number) {
          const { data } = await octokit.pulls.get({
            owner,
            repo,
            pull_number,
            mediaType: { format: "diff" },
          });
          return toolResponse(`Diff for PR #${pull_number}:\n\n\`\`\`diff\n${data}\n\`\`\``);
        }

        if (base && head) {
          const { data } = await octokit.repos.compareCommits({
            owner,
            repo,
            base,
            head,
            mediaType: { format: "diff" },
          });
          return toolResponse(`Diff ${base}...${head}:\n\n\`\`\`diff\n${data}\n\`\`\``);
        }

        return toolResponse("Provide either pull_number or both base and head.");
      } catch (error) {
        return toolError("Failed to get diff", error);
      }
    }
  );
  }

  // -- search / fetch (ChatGPT deep-research / company-knowledge compatibility) --
  // ChatGPT requires an MCP server to expose tools named exactly `search` and
  // `fetch`, returning data as BOTH structuredContent and a JSON string in the
  // content array (per OpenAI's compatibility schema). These are read-only and
  // always registered. `search` matches the user's Railway projects and (if
  // connected) GitHub repos by name; `fetch` resolves a result id to full detail.
  // Ids are namespaced so `fetch` knows how to resolve them.
  const searchFetchResult = (payload) => ({
    structuredContent: payload,
    content: [{ type: "text", text: JSON.stringify(payload) }],
  });

  server.tool(
    "search",
    "Search the user's Railway projects and connected GitHub repositories by name. Returns a list of results (id, title, url) to use with the fetch tool. Present for ChatGPT connector compatibility.",
    { query: z.string().describe("Text to match against Railway project and GitHub repo names") },
    async ({ query }) => {
      const q = (query || "").toLowerCase().trim();
      const results = [];
      try {
        const wd = await gqlRequest(gql`
          query { me { workspaces { id name } } }
        `);
        for (const w of wd.me?.workspaces || []) {
          const pd = await gqlRequest(
            gql`
              query ($w: String!) {
                projects(workspaceId: $w) {
                  edges { node { id name } }
                }
              }
            `,
            { w: w.id }
          );
          for (const e of pd.projects?.edges || []) {
            const p = e.node;
            if (!q || p.name.toLowerCase().includes(q)) {
              results.push({
                id: `railway-project:${p.id}`,
                title: `Railway project: ${p.name} (${w.name})`,
                url: `https://railway.com/project/${p.id}`,
              });
            }
          }
        }
      } catch {
        // Railway search failure shouldn't drop GitHub matches.
      }
      if (githubToken) {
        try {
          const { data } = await octokit.repos.listForAuthenticatedUser({
            per_page: 100,
            sort: "updated",
          });
          for (const r of data) {
            if (!q || r.full_name.toLowerCase().includes(q)) {
              results.push({
                id: `github-repo:${r.full_name}`,
                title: `GitHub repo: ${r.full_name}${r.private ? " (private)" : ""}`,
                url: r.html_url,
              });
            }
          }
        } catch {
          // Ignore GitHub search failures.
        }
      }
      return searchFetchResult({ results });
    }
  );

  server.tool(
    "fetch",
    "Fetch full details for a single result id from the search tool (a Railway project or a GitHub repository). Present for ChatGPT connector compatibility.",
    {
      id: z
        .string()
        .describe(
          "A result id from search, e.g. 'railway-project:<id>' or 'github-repo:<owner>/<name>'"
        ),
    },
    async ({ id }) => {
      try {
        if (id.startsWith("railway-project:")) {
          const projectId = id.slice("railway-project:".length);
          const d = await gqlRequest(
            gql`
              query ($id: String!) {
                project(id: $id) {
                  id
                  name
                  description
                  services { edges { node { name } } }
                  environments { edges { node { name } } }
                }
              }
            `,
            { id: projectId }
          );
          const p = d.project;
          if (!p) {
            return searchFetchResult({ id, title: "Not found", text: `No Railway project for ${id}.`, url: "" });
          }
          const services = p.services?.edges?.map((e) => e.node.name) || [];
          const envs = p.environments?.edges?.map((e) => e.node.name) || [];
          return searchFetchResult({
            id,
            title: `Railway project: ${p.name}`,
            text:
              `Railway project "${p.name}" (${p.id}).\n` +
              (p.description ? `Description: ${p.description}\n` : "") +
              `Services: ${services.length ? services.join(", ") : "none"}.\n` +
              `Environments: ${envs.length ? envs.join(", ") : "none"}.`,
            url: `https://railway.com/project/${p.id}`,
            metadata: { services: String(services.length), environments: String(envs.length) },
          });
        }
        if (id.startsWith("github-repo:")) {
          const [owner, repo] = id.slice("github-repo:".length).split("/");
          const { data: r } = await octokit.repos.get({ owner, repo });
          return searchFetchResult({
            id,
            title: r.full_name,
            text:
              `GitHub repository ${r.full_name}${r.private ? " (private)" : " (public)"}.\n` +
              (r.description ? `Description: ${r.description}\n` : "") +
              `Default branch: ${r.default_branch}. Language: ${r.language || "n/a"}.\n` +
              `Stars: ${r.stargazers_count}. Open issues: ${r.open_issues_count}.\n` +
              `Clone: ${r.clone_url}`,
            url: r.html_url,
            metadata: { private: String(r.private), defaultBranch: r.default_branch },
          });
        }
        return searchFetchResult({
          id,
          title: "Unknown id",
          text: `Don't know how to fetch '${id}'. Use an id returned by the search tool.`,
          url: "",
        });
      } catch (error) {
        return searchFetchResult({ id, title: "Error", text: `Failed to fetch ${id}: ${error.message}`, url: "" });
      }
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Login-with-Railway helpers
// ---------------------------------------------------------------------------

// Ensure this server has an OAuth client registered with Railway. Prefers
// explicit env credentials; otherwise self-registers via Dynamic Client
// Registration (DCR) and persists the result to the volume.
async function ensureRailwayClient() {
  if (RAILWAY_OAUTH_CLIENT_ID) {
    railwayClientReg = {
      client_id: RAILWAY_OAUTH_CLIENT_ID,
      client_secret: RAILWAY_OAUTH_CLIENT_SECRET || null,
      token_endpoint_auth_method: RAILWAY_OAUTH_CLIENT_SECRET
        ? "client_secret_basic"
        : "none",
      redirect: RAILWAY_CALLBACK,
    };
    return;
  }
  // Re-register if we have no client yet, or the callback changed (e.g. a
  // domain was assigned after the first boot).
  if (railwayClientReg?.client_id && railwayClientReg.redirect === RAILWAY_CALLBACK) return;

  try {
    const res = await fetch(RAILWAY_OIDC.register, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Self-hosted Railway MCP server",
        redirect_uris: [RAILWAY_CALLBACK],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic",
        scope: RAILWAY_OAUTH_SCOPE,
      }),
    });
    if (!res.ok) {
      console.error(
        `[railway-oauth] DCR failed (${res.status}). Set RAILWAY_OAUTH_CLIENT_ID/SECRET to register an app manually.`
      );
      return;
    }
    const data = await res.json();
    railwayClientReg = {
      client_id: data.client_id,
      client_secret: data.client_secret || null,
      token_endpoint_auth_method:
        data.token_endpoint_auth_method ||
        (data.client_secret ? "client_secret_basic" : "none"),
      redirect: RAILWAY_CALLBACK,
    };
    saveStore();
    console.log(`[railway-oauth] registered client ${railwayClientReg.client_id}`);
  } catch (err) {
    console.error("[railway-oauth] DCR error:", err.message);
  }
}

// Build a Railway token-endpoint request, honoring the client's auth method
// (confidential = HTTP Basic; public = client_id in the body).
function railwayTokenRequestInit(params) {
  const body = new URLSearchParams(params);
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (
    railwayClientReg.token_endpoint_auth_method === "client_secret_basic" &&
    railwayClientReg.client_secret
  ) {
    headers.Authorization =
      "Basic " +
      Buffer.from(
        `${railwayClientReg.client_id}:${railwayClientReg.client_secret}`
      ).toString("base64");
  } else {
    body.set("client_id", railwayClientReg.client_id);
  }
  return { method: "POST", headers, body: body.toString() };
}

async function railwayExchangeCode(code, codeVerifier) {
  const res = await fetch(
    RAILWAY_OIDC.token,
    railwayTokenRequestInit({
      grant_type: "authorization_code",
      code,
      redirect_uri: RAILWAY_CALLBACK,
      code_verifier: codeVerifier,
    })
  );
  if (!res.ok) throw new Error(`Railway token exchange failed (${res.status})`);
  return res.json();
}

async function railwayRefresh(refreshToken) {
  const res = await fetch(
    RAILWAY_OIDC.token,
    railwayTokenRequestInit({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    })
  );
  if (!res.ok) return null;
  return res.json();
}

async function railwayUserinfo(accessToken) {
  const res = await fetch(RAILWAY_OIDC.userinfo, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`Railway userinfo failed (${res.status})`);
  return res.json();
}

// Decide whether a logged-in Railway user may use this connector, locking to
// them on first use when no explicit allowlist is configured.
function isUserAllowed(me) {
  const email = (me.email || "").toLowerCase();
  // Railway's OIDC already authenticated this user; `sub` is the real identity.
  // We don't gate on email_verified — Railway returns it false even for valid
  // primary emails, so enforcing it locks out legitimate users.
  if (!me.sub) return false;
  if (ALLOWED_RAILWAY_EMAILS.length) {
    return !!email && ALLOWED_RAILWAY_EMAILS.includes(email);
  }
  if (owner?.sub) return owner.sub === me.sub;
  owner = { sub: me.sub, email };
  saveStore();
  console.log(`[auth] connector locked to ${email || me.sub} (trust-on-first-use)`);
  return true;
}

// Resolve the Railway API bearer for an incoming MCP request: the static
// override if set, otherwise the session's access token (refreshed if stale).
async function resolveRailwayAccessToken(mcpToken) {
  if (RAILWAY_API_TOKEN) return RAILWAY_API_TOKEN;
  const entry = accessTokens.get(mcpToken);
  const rw = entry?.railway;
  if (!rw) return null;
  if (Date.now() < rw.expiresAt - 60 * 1000) return rw.accessToken;
  // Access token is stale. We must refresh; if we can't, the token is dead and
  // returning it anyway just produces "Not Authorized" on every downstream call.
  // Return null instead so the caller surfaces a clear "reconnect" message.
  if (!rw.refreshToken) return null;
  const refreshed = await railwayRefresh(rw.refreshToken);
  if (refreshed?.access_token) {
    rw.accessToken = refreshed.access_token;
    if (refreshed.refresh_token) rw.refreshToken = refreshed.refresh_token;
    rw.expiresAt = Date.now() + (refreshed.expires_in || 3600) * 1000;
    saveStore();
    return rw.accessToken;
  }
  // Refresh failed (refresh token expired or revoked). Treat as logged out.
  return null;
}

// Force a Railway token refresh for a session regardless of expiry clock, used
// when a live API call comes back Not Authorized mid-session. Returns the new
// access token, or null if the session can't be refreshed (caller should tell
// the user to reconnect). Skipped entirely when a static override is in play.
async function forceRailwayRefresh(mcpToken) {
  if (RAILWAY_API_TOKEN) return null;
  const rw = accessTokens.get(mcpToken)?.railway;
  if (!rw?.refreshToken) return null;
  const refreshed = await railwayRefresh(rw.refreshToken);
  if (!refreshed?.access_token) return null;
  rw.accessToken = refreshed.access_token;
  if (refreshed.refresh_token) rw.refreshToken = refreshed.refresh_token;
  rw.expiresAt = Date.now() + (refreshed.expires_in || 3600) * 1000;
  saveStore();
  return rw.accessToken;
}

// ---------------------------------------------------------------------------
// GitHub App device flow (github-connect)
// ---------------------------------------------------------------------------

// Start a device-flow authorization; returns { user_code, verification_uri,
// device_code, interval, expires_in }.
async function githubDeviceStart() {
  const res = await fetch(GITHUB_DEVICE.code, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: GITHUB_OAUTH_CLIENT_ID }),
  });
  if (!res.ok) throw new Error(`device code request failed (${res.status})`);
  const d = await res.json();
  if (d.error) throw new Error(d.error_description || d.error);
  return d;
}

// Poll GitHub in the background until the user authorizes, then store the token.
function startGitHubDevicePoll(d) {
  pendingGitHub = {
    device_code: d.device_code,
    expiresAt: Date.now() + (d.expires_in || 900) * 1000,
  };
  let interval = (d.interval || 5) * 1000;
  const poll = async () => {
    if (!pendingGitHub || Date.now() > pendingGitHub.expiresAt) {
      pendingGitHub = null;
      return;
    }
    try {
      const res = await fetch(GITHUB_DEVICE.token, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: GITHUB_OAUTH_CLIENT_ID,
          device_code: pendingGitHub.device_code,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        }),
      });
      const t = await res.json();
      if (t.access_token) {
        githubAuth = {
          accessToken: t.access_token,
          refreshToken: t.refresh_token || null,
          expiresAt: t.expires_in ? Date.now() + t.expires_in * 1000 : null,
          login: null,
        };
        pendingGitHub = null;
        saveStore();
        try {
          const me = await new Octokit({ auth: t.access_token }).users.getAuthenticated();
          githubAuth.login = me.data.login;
          saveStore();
          console.log(`[github] connected as ${me.data.login}`);
        } catch {
          console.log("[github] connected (login lookup failed)");
        }
        return;
      }
      if (t.error === "slow_down") interval += 5000;
      else if (t.error === "expired_token" || t.error === "access_denied") {
        console.log(`[github] device flow ${t.error}`);
        pendingGitHub = null;
        return;
      }
      // otherwise authorization_pending — keep polling
    } catch (e) {
      console.error("[github] poll error:", e.message);
    }
    setTimeout(poll, interval);
  };
  setTimeout(poll, interval);
}

async function refreshGitHubToken(refreshToken) {
  try {
    const res = await fetch(GITHUB_DEVICE.token, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: GITHUB_OAUTH_CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }),
    });
    const t = await res.json();
    if (t.access_token) {
      githubAuth = {
        ...githubAuth,
        accessToken: t.access_token,
        refreshToken: t.refresh_token || githubAuth.refreshToken,
        expiresAt: t.expires_in ? Date.now() + t.expires_in * 1000 : null,
      };
      saveStore();
      return t.access_token;
    }
  } catch (e) {
    console.error("[github] refresh failed:", e.message);
  }
  return null;
}

// Resolve the GitHub bearer for a request: connected device-flow token
// (refreshed if stale), else the static GITHUB_TOKEN, else null.
async function resolveGitHubToken() {
  if (githubAuth?.accessToken) {
    if (!githubAuth.expiresAt || Date.now() < githubAuth.expiresAt - 60 * 1000) {
      return githubAuth.accessToken;
    }
    if (githubAuth.refreshToken) {
      const fresh = await refreshGitHubToken(githubAuth.refreshToken);
      if (fresh) return fresh;
    }
    return githubAuth.accessToken;
  }
  if (GITHUB_TOKEN) return GITHUB_TOKEN;
  return null;
}

// ---------------------------------------------------------------------------
// Express app with OAuth
// ---------------------------------------------------------------------------
const app = express();

// Railway (and most platforms) put the server behind a proxy. Without this,
// req.ip would be the proxy's IP and the rate limiter would be useless.
app.set("trust proxy", true);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// --- Health ---
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// --- Landing page: shows the deployer their connector URL + how to add it ---
// Public (unauthenticated) — exposes only the already-public /mcp URL and
// whether GitHub tools are on. No secrets, allowlist, or owner info here.
app.get("/", (_req, res) => {
  const mcpUrl = `${PUBLIC_URL}/mcp`;
  const ghEnabled = !!githubAuth?.accessToken || !!GITHUB_TOKEN;
  const tokenLink =
    "https://github.com/settings/tokens/new?scopes=repo&description=Railway-GitHub-MCP";

  const ghPro = ghEnabled
    ? `<div class="note">✓ GitHub tools are <b>enabled</b>. Custom connectors require a paid Claude plan.</div>`
    : `<div class="note"><b>GitHub is optional</b> (Railway tools work without it). Easiest: ask Claude to run <code>github-connect</code> — it walks you through installing the app + picking repos, no token to paste. Or set a <code>GITHUB_TOKEN</code> variable manually. Custom connectors require a paid Claude plan.</div>`;

  const ghNew = ghEnabled
    ? `<li><b>GitHub is already connected</b> ✓ — you can also ask Claude to read and write your code (e.g. "create a repo and push a hello-world app").</li>`
    : `<li><b>Optional: connect GitHub</b> so Claude can store and write your code (create repos, commit files, open pull requests):
        <ol class="sub-ol">
          <li><b>Easiest:</b> once you've added the connector and logged in, ask Claude to run <code>github-connect</code>. It gives you a link to install the app (pick which repos it can touch) and a code to authorize — no token to copy. New to GitHub? <a href="https://github.com/signup" target="_blank" rel="noopener">Sign up free</a> first.</li>
          <li><b>Or manually:</b> <a href="${tokenLink}" target="_blank" rel="noopener">create a token</a> (<code>repo</code> pre-selected) and set it as a <code>GITHUB_TOKEN</code> variable on this service.</li>
        </ol>
        You can skip this for now and add it anytime.</li>`;

  res.type("html").send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Railway + GitHub MCP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; min-height: 100vh; display: flex;
    align-items: center; justify-content: center; padding: 24px;
    background: linear-gradient(135deg, #8B6CFF, #5326CC); color: #1c1f26; }
  .card { background: #fff; border-radius: 16px; padding: 2rem; max-width: 560px; width: 100%;
    box-shadow: 0 8px 40px rgba(0,0,0,.18); }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  .sub { color: #666; font-size: .95rem; margin-bottom: 1.25rem; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid #eee; margin-bottom: 1.25rem; }
  .tab { background: none; color: #777; border: none; border-bottom: 2px solid transparent;
    border-radius: 0; padding: .55rem .8rem; font-size: .9rem; font-weight: 600; cursor: pointer; }
  .tab:hover { background: none; color: #1c1f26; }
  .tab.active { color: #6A45F0; border-bottom-color: #6A45F0; }
  label { font-size: .8rem; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: #6A45F0; }
  .url { display: flex; gap: 8px; margin: .5rem 0 1.25rem; }
  .url code { flex: 1; background: #f3f0fb; border: 1px solid #e0d8f5; border-radius: 8px;
    padding: .7rem .8rem; font-family: ui-monospace, Menlo, monospace; font-size: .88rem;
    overflow-x: auto; white-space: nowrap; }
  button { background: #6A45F0; color: #fff; border: none; border-radius: 8px; padding: 0 1rem;
    font-size: .85rem; font-weight: 600; cursor: pointer; white-space: nowrap; }
  button:hover { background: #5a37d8; }
  ol, ul { margin: 0 0 1rem 1.1rem; font-size: .92rem; line-height: 1.7; }
  .sub-ol { margin: .4rem 0 .5rem 1.1rem; }
  .what { background: #f9f8fd; border: 1px solid #eee; border-radius: 10px; padding: .9rem 1rem;
    margin-bottom: 1.25rem; font-size: .92rem; line-height: 1.55; }
  .what p { margin-bottom: .5rem; }
  .what ul { margin: .3rem 0 .5rem 1.2rem; }
  .note { font-size: .85rem; color: #555; background: #f6f4fb; border-radius: 8px; padding: .7rem .8rem; }
  a { color: #6A45F0; }
  .try { margin-top: 1.5rem; border-top: 1px solid #eee; padding-top: 1.25rem; }
  .try label { display: block; margin-bottom: .5rem; }
  .try .prompt { display: flex; gap: 8px; align-items: stretch; }
  .try .prompt p { flex: 1; background: #f3f0fb; border: 1px solid #e0d8f5; border-radius: 8px;
    padding: .7rem .8rem; font-size: .9rem; line-height: 1.5; color: #2a2440; }
  .try .prompt button { align-self: stretch; }
  .try .hint { font-size: .8rem; color: #777; margin-top: .5rem; }
  [hidden] { display: none; }
</style></head>
<body>
  <div class="card">
    <h1>Railway + GitHub MCP</h1>
    <div class="sub">A Claude connector that builds and ships apps for you — it manages Railway (hosting) and, optionally, GitHub (your code).</div>

    <div class="tabs">
      <button class="tab active" onclick="showTab('new', this)">I'm new to this</button>
      <button class="tab" onclick="showTab('pro', this)">I know what I'm doing</button>
    </div>

    <div id="pro" class="pane" hidden>
      <label>Add this connector to Claude</label>
      <div class="url"><code>${mcpUrl}</code><button onclick="copyUrl(this)">Copy</button></div>
      <ol>
        <li>Claude → <b>Settings → Connectors → Add custom connector</b></li>
        <li>Paste the URL, save</li>
        <li><b>Connect</b> → <b>Log in with Railway</b></li>
      </ol>
      ${ghPro}
    </div>

    <div id="new" class="pane">
      <div class="what">
        <p><b>What this is.</b> A "connector" gives Claude (the AI you chat with) the ability to act in:</p>
        <ul>
          <li><b>Railway</b> — where your app actually runs (servers, database, deploys).</li>
          <li><b>GitHub</b> — where your code is stored. Optional; add it whenever.</li>
        </ul>
        <p>You describe what you want in plain English, and Claude creates the project, writes the code, and deploys it — acting as you, securely.</p>
      </div>

      <label>Get set up</label>
      <ol>
        <li>You'll need a <b>paid Claude plan</b> (Pro or above) — custom connectors aren't on the free tier.</li>
        <li>Copy this connector address:
          <div class="url"><code>${mcpUrl}</code><button onclick="copyUrl(this)">Copy</button></div>
        </li>
        <li>In Claude, go to <b>Settings → Connectors → Add custom connector</b>, paste the address, and save.</li>
        <li>Click <b>Connect</b>, then <b>Log in with Railway</b> and approve. That's it — try asking Claude <i>"list my Railway projects."</i></li>
        ${ghNew}
      </ol>
    </div>

    <div class="try">
      <label>✨ Try this first</label>
      <div class="prompt">
        <p>Build me a website that explains how easy it is to start coding in Claude with Railway. Include an animated chart, and a link to the Railway template so others can deploy their own. Then deploy it to Railway and send me the live URL.</p>
        <button onclick="copyText(this)">Copy</button>
      </div>
      <div class="hint">Paste this to Claude once the connector is connected. It builds a real site and ships it live, all from one message.</div>
    </div>
  </div>
  <script>
    function showTab(id, btn) {
      document.querySelectorAll('.pane').forEach(function (p) { p.hidden = p.id !== id; });
      document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
      btn.classList.add('active');
    }
    function copyUrl(btn) {
      navigator.clipboard.writeText(btn.previousElementSibling.textContent);
      btn.textContent = 'Copied';
    }
    function copyText(btn) {
      navigator.clipboard.writeText(btn.previousElementSibling.textContent.trim());
      btn.textContent = 'Copied';
    }
  </script>
</body></html>`);
});

// --- RFC 9728: Protected Resource Metadata ---
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: PUBLIC_URL,
    authorization_servers: [PUBLIC_URL],
    bearer_methods_supported: ["header"],
  });
});

// --- RFC 8414: Authorization Server Metadata ---
app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: PUBLIC_URL,
    authorization_endpoint: `${PUBLIC_URL}/oauth/authorize`,
    token_endpoint: `${PUBLIC_URL}/oauth/token`,
    registration_endpoint: `${PUBLIC_URL}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
  });
});

// --- RFC 7591: Dynamic Client Registration ---
app.post("/oauth/register", (req, res) => {
  const { redirect_uris, client_name } = req.body || {};

  if (
    !redirect_uris ||
    !Array.isArray(redirect_uris) ||
    redirect_uris.length === 0
  ) {
    return res.status(400).json({
      error: "invalid_client_metadata",
      error_description: "redirect_uris is required",
    });
  }

  const clientId = generateId(16);
  const client = {
    client_id: clientId,
    redirect_uris,
    client_name: client_name || "unknown",
  };
  registeredClients.set(clientId, client);
  saveStore();

  res
    .status(201)
    .json({ client_id: clientId, redirect_uris, client_name: client.client_name });
});

// --- Authorization: kick off Login with Railway ---
app.get("/oauth/authorize", (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    response_type,
  } = req.query;

  if (response_type !== "code") return res.status(400).send("Unsupported response_type");
  if (!client_id || !registeredClients.has(client_id)) return res.status(400).send("Unknown client_id");
  if (!code_challenge || code_challenge_method !== "S256") return res.status(400).send("PKCE with S256 is required");

  const client = registeredClients.get(client_id);
  if (!client.redirect_uris.includes(redirect_uri)) return res.status(400).send("Invalid redirect_uri");

  if (!railwayClientReg?.client_id) {
    return res
      .status(503)
      .send(
        "Login with Railway is not configured. Set RAILWAY_OAUTH_CLIENT_ID/SECRET, or check the DCR registration logs."
      );
  }

  // Stash the Claude-side request, then start the Railway login leg with our
  // own PKCE pair (we are a client of Railway here).
  const railwayState = generateId(16);
  const railwayVerifier = base64url(crypto.randomBytes(32));
  const railwayChallenge = base64url(sha256(railwayVerifier));
  pendingAuth.set(railwayState, {
    claudeClientId: client_id,
    claudeRedirectUri: redirect_uri,
    claudeState: state,
    claudeCodeChallenge: code_challenge,
    railwayVerifier,
    createdAt: Date.now(),
  });

  const u = new URL(RAILWAY_OIDC.authorize);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", railwayClientReg.client_id);
  u.searchParams.set("redirect_uri", RAILWAY_CALLBACK);
  u.searchParams.set("scope", RAILWAY_OAUTH_SCOPE);
  u.searchParams.set("state", railwayState);
  u.searchParams.set("code_challenge", railwayChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  res.redirect(302, u.toString());
});

// --- Railway login callback: verify identity, then resume the Claude flow ---
app.get("/oauth/railway/callback", async (req, res) => {
  const ip = req.ip || "unknown";
  const ua = req.headers["user-agent"] || "unknown";
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).type("text/plain").send(`Railway login failed: ${error}`);
  }

  const pend = pendingAuth.get(state);
  if (!pend || Date.now() - pend.createdAt > PENDING_AUTH_TTL) {
    pendingAuth.delete(state);
    return res
      .status(400)
      .type("text/plain")
      .send("Login session expired. Please reconnect from Claude.");
  }
  pendingAuth.delete(state);

  try {
    const tok = await railwayExchangeCode(code, pend.railwayVerifier);
    const me = await railwayUserinfo(tok.access_token);

    if (!isUserAllowed(me)) {
      console.log(`[AUTH-DENY] ip=${ip} email=${me.email}`);
      sendDiscordAlert({
        title: "⛔ Login denied (not on allowlist)",
        description: "A Railway user authenticated but is not allowed to use this connector.",
        color: 0xED4245,
        fields: [
          { name: "Email", value: `\`${truncate(me.email || "?", 128)}\``, inline: true },
          { name: "IP", value: `\`${ip}\``, inline: true },
          { name: "User-Agent", value: truncate(ua, 256), inline: false },
        ],
        dedupeKey: `denied:${me.sub || ip}`,
      });
      return res.status(403).type("html").send(deniedPage(me.email));
    }

    const railway = {
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token || null,
      expiresAt: Date.now() + (tok.expires_in || 3600) * 1000,
      sub: me.sub,
      email: (me.email || "").toLowerCase(),
    };

    // Mint our own auth code for Claude, carrying the Railway session with it.
    const mcpCode = generateId(32);
    authCodes.set(mcpCode, {
      clientId: pend.claudeClientId,
      codeChallenge: pend.claudeCodeChallenge,
      redirectUri: pend.claudeRedirectUri,
      expiresAt: Date.now() + AUTH_CODE_TTL,
      railway,
    });

    const redirectUrl = new URL(pend.claudeRedirectUri);
    redirectUrl.searchParams.set("code", mcpCode);
    if (pend.claudeState) redirectUrl.searchParams.set("state", pend.claudeState);
    res.redirect(302, redirectUrl.toString());
  } catch (err) {
    console.error("[railway-oauth] callback error:", err.message);
    res.status(502).type("text/plain").send("Login with Railway failed. Please try again.");
  }
});

// --- Token endpoint ---
app.post("/oauth/token", (req, res) => {
  const { grant_type, code, code_verifier, client_id, redirect_uri, refresh_token } = req.body;

  if (grant_type === "authorization_code") {
    if (!code || !code_verifier || !client_id) {
      return res.status(400).json({ error: "invalid_request" });
    }

    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: "invalid_grant" });
    authCodes.delete(code);

    if (entry.expiresAt < Date.now()) return res.status(400).json({ error: "invalid_grant", error_description: "Code expired" });
    if (entry.clientId !== client_id) return res.status(400).json({ error: "invalid_grant", error_description: "Client mismatch" });
    if (entry.redirectUri !== redirect_uri) return res.status(400).json({ error: "invalid_grant", error_description: "Redirect mismatch" });
    if (!verifyPkce(code_verifier, entry.codeChallenge)) return res.status(400).json({ error: "invalid_grant", error_description: "PKCE failed" });

    const token = generateId(32);
    const refresh = generateId(32);
    accessTokens.set(token, { clientId: client_id, expiresAt: Date.now() + ACCESS_TOKEN_TTL, railway: entry.railway });
    refreshTokens.set(refresh, { clientId: client_id, expiresAt: Date.now() + REFRESH_TOKEN_TTL, railway: entry.railway });
    saveStore();

    return res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000),
      refresh_token: refresh,
    });
  }

  if (grant_type === "refresh_token") {
    if (!refresh_token || !client_id) return res.status(400).json({ error: "invalid_request" });

    const entry = refreshTokens.get(refresh_token);
    if (!entry) return res.status(400).json({ error: "invalid_grant" });
    if (entry.expiresAt < Date.now()) {
      refreshTokens.delete(refresh_token);
      return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token expired" });
    }
    if (entry.clientId !== client_id) return res.status(400).json({ error: "invalid_grant" });

    refreshTokens.delete(refresh_token);
    const newToken = generateId(32);
    const newRefresh = generateId(32);
    accessTokens.set(newToken, { clientId: client_id, expiresAt: Date.now() + ACCESS_TOKEN_TTL, railway: entry.railway });
    refreshTokens.set(newRefresh, { clientId: client_id, expiresAt: Date.now() + REFRESH_TOKEN_TTL, railway: entry.railway });
    saveStore();

    return res.json({
      access_token: newToken,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000),
      refresh_token: newRefresh,
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

// --- Auth middleware ---
function checkAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res
      .status(401)
      .set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`
      )
      .json({ error: "Unauthorized" });
  }

  const token = auth.slice(7);
  const entry = accessTokens.get(token);
  if (!entry || entry.expiresAt < Date.now()) {
    if (entry) { accessTokens.delete(token); saveStore(); }
    return res
      .status(401)
      .set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`
      )
      .json({ error: "Invalid or expired token" });
  }

  // Stash the token on req so downstream handlers can use it (for activity logging).
  req.authToken = token;
  next();
}

// --- MCP endpoint ---
app.post("/mcp", checkAuth, async (req, res) => {
  try {
    // Log/alert on MCP activity before handing off to the transport.
    // Wrapped in try/catch so activity logging bugs never break MCP traffic.
    try {
      logMcpActivity({ req, token: req.authToken, body: req.body });
    } catch (err) {
      console.error("[mcp-activity] logging failed:", err.message);
    }

    const railwayToken = await resolveRailwayAccessToken(req.authToken);
    if (!railwayToken) {
      return res.status(401).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Railway session expired or missing. Reconnect this connector in Claude.",
        },
        id: req.body?.id ?? null,
      });
    }

    const githubToken = await resolveGitHubToken();

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const server = createRailwayMcpServer(railwayToken, githubToken, req.authToken);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("[Error] Request handling failed:", err);
    res.status(500).json({
      jsonrpc: "2.0",
      error: { code: -32603, message: "Internal server error" },
      id: null,
    });
  }
});

app.get("/mcp", (_req, res) => {
  res.status(405).set("Allow", "POST").send("Method Not Allowed");
});

// ---------------------------------------------------------------------------
// Access-denied page (shown when a Railway user is not on the allowlist)
// ---------------------------------------------------------------------------
function deniedPage(email) {
  const who = email ? String(email).replace(/[<>&]/g, "") : "this account";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access denied — Railway MCP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; padding: 2rem; max-width: 380px; width: 100%; box-shadow: 0 2px 12px rgba(0,0,0,.08); text-align: center; }
  h1 { font-size: 1.25rem; margin-bottom: .5rem; }
  p { font-size: .9rem; color: #555; line-height: 1.5; }
  code { background: #f0f0f0; padding: .1rem .3rem; border-radius: 4px; }
</style>
</head>
<body>
<div class="card">
  <h1>Access denied</h1>
  <p><code>${who}</code> is not authorized to use this connector. It is private to its owner. If this is your server, add your Railway email to <code>ALLOWED_RAILWAY_EMAILS</code>.</p>
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
ensureRailwayClient().finally(() => {
  const httpServer = app.listen(PORT, () => {
    console.log(`Railway MCP server listening on port ${PORT}`);
    console.log(`Public URL: ${PUBLIC_URL}`);
    console.log("Auth: Login with Railway (OAuth 2.0 / OIDC + PKCE)");
    console.log(`Capabilities: RAILWAY_MODE=${RAILWAY_MODE}, GITHUB_MODE=${GITHUB_MODE}`);
    console.log(
      `GitHub: ${
        githubAuth?.accessToken
          ? `connected as ${githubAuth.login || "?"}`
          : GITHUB_TOKEN
          ? "static GITHUB_TOKEN"
          : "not connected (use github-connect)"
      }`
    );
    console.log(
      `Railway OAuth client: ${railwayClientReg?.client_id || "NOT REGISTERED — set RAILWAY_OAUTH_CLIENT_ID/SECRET"}`
    );
    console.log(`Scope: ${RAILWAY_OAUTH_SCOPE}`);
    console.log(
      `API calls run as: ${RAILWAY_API_TOKEN ? "static RAILWAY_API_TOKEN" : "the logged-in user"}`
    );
    console.log(
      `Allowlist: ${
        ALLOWED_RAILWAY_EMAILS.length
          ? ALLOWED_RAILWAY_EMAILS.join(", ")
          : owner
          ? `${owner.email} (locked)`
          : "trust-on-first-use (open until first login)"
      }`
    );
    console.log(`Discord alerts: ${DISCORD_WEBHOOK_URL ? "enabled" : "disabled (no DISCORD_WEBHOOK_URL)"}`);
    console.log(`MCP activity alerts: ${MCP_ACTIVITY_ALERTS ? "ON" : "OFF (set MCP_ACTIVITY_ALERTS=true to enable)"}`);
  });

  // Graceful shutdown: Railway sends SIGTERM when redeploying/stopping. Close the
  // HTTP server and exit 0 so the process ends cleanly instead of being killed by
  // signal (which makes npm print noisy "npm error signal SIGTERM" lines).
  const shutdown = (signal) => {
    console.log(`Received ${signal}, shutting down gracefully`);
    httpServer.close(() => process.exit(0));
    // Hard cap in case a connection hangs the close().
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
});
