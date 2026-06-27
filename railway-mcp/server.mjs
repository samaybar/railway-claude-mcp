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
//   - query-postgres: SQL is unconstrained; can be read OR write, always alert
//   - list-variables: returns plaintext env var values (including secrets);
//     effectively a secrets exfiltration tool, always alert
const DESTRUCTIVE_TOOLS = new Set([
  "create-project",
  "create-environment",
  "create-service-from-github",
  "delete-service",
  "set-variables",
  "list-variables",
  "redeploy-service",
  "deploy-template",
  "generate-domain",
  "query-postgres",
  "create-volume",
  "delete-volume",
]);

// Tools that get an extra-attention red color rather than orange.
// list-variables is critical because anyone calling it with reveal=true can
// dump every secret on the service in one call (API keys, DB connection
// strings, etc). Values are masked by default.
const CRITICAL_TOOLS = new Set([
  "delete-service",
  "delete-volume",
  "set-variables",
  "list-variables",
  "query-postgres",
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
    case "create-project":
      return `name=${a.name || "?"}`;
    case "create-environment":
      return `project=${a.projectId || "?"} name=${a.name || "?"}`;
    case "create-service-from-github":
      return `project=${a.projectId || "?"} repo=${a.repo || "?"}${a.branch ? `@${a.branch}` : ""}`;
    case "delete-service":
      return `service=${a.serviceId || "?"}`;
    case "set-variables": {
      const keys = a.variables ? Object.keys(a.variables) : [];
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"} vars=[${keys.join(", ")}]`;
    }
    case "list-variables":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"}${a.environmentId ? ` env=${a.environmentId}` : ""}`;
    case "redeploy-service":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"}`;
    case "deploy-template":
      return `template=${a.templateId || "?"}${a.projectId ? ` project=${a.projectId}` : " (new project)"}`;
    case "generate-domain":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"}${a.targetPort ? ` port=${a.targetPort}` : ""}`;
    case "query-postgres": {
      // Show the first line of the SQL so you can eyeball SELECT vs. DROP
      // without the full payload bleeding into chat.
      const sql = (a.sql || "").replace(/\s+/g, " ").trim();
      return `sql=${truncate(sql, 160)}`;
    }
    case "create-volume":
      return `project=${a.projectId || "?"} service=${a.serviceId || "?"} mount=${a.mountPath || "?"}`;
    case "delete-volume":
      return `volume=${a.volumeId || "?"}`;
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
function createRailwayMcpServer(railwayToken) {
  const server = new McpServer(
    {
      name: "railway-mcp-server-remote",
      title: "Railway MCP Server (Remote)",
      version: "1.0.0",
    },
    { capabilities: { logging: {} } }
  );

  const railwayClient = new GraphQLClient(
    "https://backboard.railway.com/graphql/v2",
    {
      headers: {
        Authorization: `Bearer ${railwayToken}`,
        "x-source": "railway-mcp-server-remote",
      },
    }
  );

  async function gqlRequest(query, variables) {
    return railwayClient.request(query, variables);
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

  // -- list-workspaces --
  server.tool(
    "list-workspaces",
    "List the Railway workspaces this connector can access (the ones you granted at login). Use a workspace id with list-projects or create-project.",
    {},
    { title: "List workspaces", readOnlyHint: true, openWorldHint: true },
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
        return toolResponse(`Failed to list workspaces: ${error.message}`);
      }
    }
  );

  // -- list-projects --
  server.tool(
    "list-projects",
    "List Railway projects. Login-with-Railway scopes this connector to the workspaces you granted, so projects are listed per workspace. Pass workspaceId (from list-workspaces) to scope to one.",
    {
      workspaceId: z
        .string()
        .optional()
        .describe("Limit to a single workspace id (from list-workspaces)."),
    },
    { title: "List projects", readOnlyHint: true, openWorldHint: true },
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
        return toolResponse(`Failed to list projects: ${error.message}`);
      }
    }
  );

  // -- create-project --
  server.tool(
    "create-project",
    "Create a new Railway project. With Login-with-Railway auth, pass workspaceId (from list-workspaces) so it lands in a workspace you can access.",
    {
      name: z.string().describe("Name for the new project"),
      workspaceId: z
        .string()
        .optional()
        .describe(
          "Workspace id to create the project in (from list-workspaces)."
        ),
    },
    { title: "Create project", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
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
        return toolResponse(`Failed to create project: ${error.message}`);
      }
    }
  );

  // -- get-project --
  server.tool(
    "get-project",
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
        return toolResponse(`Failed to get project: ${error.message}`);
      }
    }
  );

  // -- list-services --
  server.tool(
    "list-services",
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

        const formatted = services
          .map((s) => `- **${s.name}** (ID: ${s.id})`)
          .join("\n");

        return toolResponse(
          `Found ${services.length} service(s):\n\n${formatted}`
        );
      } catch (error) {
        return toolResponse(`Failed to list services: ${error.message}`);
      }
    }
  );

  // -- list-variables --
  server.tool(
    "list-variables",
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
        return toolResponse(`Failed to list variables: ${error.message}`);
      }
    }
  );

  // -- set-variables --
  server.tool(
    "set-variables",
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
        return toolResponse(`Failed to set variables: ${error.message}`);
      }
    }
  );

  // -- get-logs --
  server.tool(
    "get-logs",
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
        return toolResponse(`Failed to get logs: ${error.message}`);
      }
    }
  );

  // -- list-deployments --
  server.tool(
    "list-deployments",
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
        return toolResponse(`Failed to list deployments: ${error.message}`);
      }
    }
  );

  // -- generate-domain --
  server.tool(
    "generate-domain",
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
        return toolResponse(`Failed to generate domain: ${error.message}`);
      }
    }
  );

  // -- list-domains --
  server.tool(
    "list-domains",
    "List the domains attached to a service: both Railway-provided domains (the *.up.railway.app hosts) and any custom domains. environmentId defaults to the project's production environment. Read-only counterpart to generate-domain — use it to find a service's public URL.",
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
        const data = await gqlRequest(
          gql`
            query ($projectId: String!, $environmentId: String!, $serviceId: String!) {
              domains(
                projectId: $projectId
                environmentId: $environmentId
                serviceId: $serviceId
              ) {
                serviceDomains {
                  id
                  domain
                  targetPort
                }
                customDomains {
                  id
                  domain
                  targetPort
                  status {
                    dnsRecords {
                      hostlabel
                      recordType
                      requiredValue
                      currentValue
                      status
                    }
                  }
                }
              }
            }
          `,
          { projectId, environmentId: envId, serviceId }
        );

        const svc = data.domains?.serviceDomains || [];
        const custom = data.domains?.customDomains || [];

        if (svc.length === 0 && custom.length === 0) {
          return toolResponse(
            "No domains found for this service. Use generate-domain to create one."
          );
        }

        const fmtPort = (p) => (p ? ` → port ${p}` : "");
        const lines = [];

        if (svc.length) {
          lines.push("**Railway domains:**");
          for (const d of svc) {
            lines.push(`- https://${d.domain}${fmtPort(d.targetPort)}`);
          }
        }
        if (custom.length) {
          if (lines.length) lines.push("");
          lines.push("**Custom domains:**");
          for (const d of custom) {
            const records = d.status?.dnsRecords || [];
            const ok =
              records.length > 0 &&
              records.every((r) => (r.status || "").toUpperCase() === "VALID");
            const state = records.length
              ? ok
                ? "verified"
                : "pending DNS"
              : "no DNS records";
            lines.push(`- https://${d.domain}${fmtPort(d.targetPort)} (${state})`);
          }
        }

        return toolResponse(lines.join("\n"));
      } catch (error) {
        return toolResponse(`Failed to list domains: ${error.message}`);
      }
    }
  );

  // -- create-environment --
  server.tool(
    "create-environment",
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
        return toolResponse(`Failed to create environment: ${error.message}`);
      }
    }
  );

  // -- deploy-template --
  server.tool(
    "deploy-template",
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
        return toolResponse(`Failed to deploy template: ${error.message}`);
      }
    }
  );

  // -- check-railway-status --
  server.tool(
    "check-railway-status",
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

  // -- redeploy-service --
  server.tool(
    "redeploy-service",
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
          return toolResponse("No previous deployment found to redeploy.");
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
        return toolResponse(`Failed to redeploy: ${error.message}`);
      }
    }
  );

  // -- create-service-from-github --
  server.tool(
    "create-service-from-github",
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
              `Try using redeploy-service to manually trigger deployment.`
          );
        }

        return toolResponse(
          `Service created and deployment triggered!\n\n` +
            `**${service.name}** (ID: ${service.id})\n` +
            `Repository: ${repo} (branch: ${branch || "main"})\n` +
            `Environment: ${envId}\n\n` +
            `Use list-deployments to check build progress.`
        );
      } catch (error) {
        return toolResponse(`Failed to create service: ${error.message}`);
      }
    }
  );

  // -- delete-service --
  server.tool(
    "delete-service",
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
        return toolResponse(`Failed to delete service: ${error.message}`);
      }
    }
  );

  // -- query-postgres --
  server.tool(
    "query-postgres",
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

  // -- volume tools (create-volume, list-volumes, delete-volume) --
  registerVolumeTools(server, { gqlRequest, resolveEnvironmentId });

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
  if (!rw.refreshToken) return rw.accessToken;
  const refreshed = await railwayRefresh(rw.refreshToken);
  if (refreshed?.access_token) {
    rw.accessToken = refreshed.access_token;
    if (refreshed.refresh_token) rw.refreshToken = refreshed.refresh_token;
    rw.expiresAt = Date.now() + (refreshed.expires_in || 3600) * 1000;
    saveStore();
  }
  return rw.accessToken;
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

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const server = createRailwayMcpServer(railwayToken);
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
  app.listen(PORT, () => {
    console.log(`Railway MCP server listening on port ${PORT}`);
    console.log(`Public URL: ${PUBLIC_URL}`);
    console.log("Auth: Login with Railway (OAuth 2.0 / OIDC + PKCE)");
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
});
