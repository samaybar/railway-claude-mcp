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
const RAILWAY_API_TOKEN = process.env.RAILWAY_API_TOKEN;
const AUTH_PASSWORD = process.env.AUTH_PASSWORD;
const PUBLIC_URL = (
  process.env.PUBLIC_URL || `http://localhost:${PORT}`
).replace(/\/$/, "");
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";

// Parse a truthy env var: accepts true/1/yes/on (case-insensitive).
// Anything else (including unset) is falsy. Defaults to OFF so merging this
// does not suddenly flood the channel.
function parseBool(v) {
  if (!v) return false;
  return ["true", "1", "yes", "on"].includes(String(v).trim().toLowerCase());
}
const MCP_ACTIVITY_ALERTS = parseBool(process.env.MCP_ACTIVITY_ALERTS);

if (!RAILWAY_API_TOKEN) {
  console.error("Error: RAILWAY_API_TOKEN environment variable is required");
  process.exit(1);
}

if (!AUTH_PASSWORD) {
  console.error("Error: AUTH_PASSWORD environment variable is required");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Railway GraphQL client
// ---------------------------------------------------------------------------
const railwayClient = new GraphQLClient(
  "https://backboard.railway.com/graphql/v2",
  {
    headers: {
      Authorization: `Bearer ${RAILWAY_API_TOKEN}`,
      "x-source": "railway-mcp-server-remote",
    },
  }
);

// ---------------------------------------------------------------------------
// Persistent OAuth storage
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.DATA_DIR || "./data";
const STORE_PATH = path.join(DATA_DIR, "auth-store.json");

const registeredClients = new Map();
const authCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

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
    console.log(
      `Loaded ${registeredClients.size} clients, ${accessTokens.size} access tokens, ${refreshTokens.size} refresh tokens`
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
// list-variables is critical because anyone calling it can dump every secret
// on the service in one call (including AUTH_PASSWORD, RAILWAY_API_TOKEN, DB
// connection strings, etc).
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
// Railway API helpers
// ---------------------------------------------------------------------------
async function gqlRequest(query, variables) {
  return railwayClient.request(query, variables);
}

/**
 * Resolve an environment ID for a project.
 * If `environmentId` is provided, returns it as-is.
 * Otherwise, fetches the project's environments and returns the one named
 * "production", falling back to the first environment if "production" is
 * not present.
 */
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

// ---------------------------------------------------------------------------
// MCP Server with Railway tools
// ---------------------------------------------------------------------------
function createRailwayMcpServer() {
  const server = new McpServer(
    {
      name: "railway-mcp-server-remote",
      title: "Railway MCP Server (Remote)",
      version: "1.0.0",
    },
    { capabilities: { logging: {} } }
  );

  // -- list-projects --
  server.tool("list-projects", "List all Railway projects", {}, async () => {
    try {
      const data = await gqlRequest(gql`
        query {
          projects {
            edges {
              node {
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
                    }
                  }
                }
              }
            }
          }
        }
      `);

      const allProjects =
        data.projects?.edges?.map((e) => e.node) || [];

      const formatted = allProjects
        .map(
          (p) =>
            `**${p.name}** (ID: ${p.id})\n` +
            `Description: ${p.description || "none"}\n` +
            `Environments: ${p.environments?.edges?.map((e) => e.node.name).join(", ") || "none"}\n` +
            `Services: ${p.services?.edges?.map((e) => e.node.name).join(", ") || "none"}\n` +
            `Created: ${new Date(p.createdAt).toLocaleDateString()}\n`
        )
        .join("\n");

      return toolResponse(
        `Found ${allProjects.length} project(s):\n\n${formatted}`
      );
    } catch (error) {
      return toolResponse(`Failed to list projects: ${error.message}`);
    }
  });

  // -- create-project --
  server.tool(
    "create-project",
    "Create a new Railway project",
    { name: z.string().describe("Name for the new project") },
    async ({ name }) => {
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
          { input: { name } }
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

// --- Authorization: GET shows login form ---
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

  res.type("html").send(authPage({ client_id, redirect_uri, state, code_challenge }));
});

// --- Authorization: POST handles form (rate limited) ---
app.post("/oauth/authorize", (req, res) => {
  const ip = req.ip || "unknown";
  const ua = req.headers["user-agent"] || "unknown";

  // --- Rate limit check (before anything else) ---
  const rl = checkRateLimit(ip);
  if (rl.limited) {
    console.log(`[RATE-LIMIT] ip=${ip} window=${rl.window} count=${rl.count}`);
    sendDiscordAlert({
      title: "🚨 Authorize endpoint rate-limited",
      description: `An IP hit the rate limit on \`POST /oauth/authorize\`.`,
      color: 0xED4245, // red
      fields: [
        { name: "IP", value: `\`${ip}\``, inline: true },
        { name: "Window", value: rl.window, inline: true },
        { name: "Attempts", value: String(rl.count), inline: true },
        { name: "User-Agent", value: ua.slice(0, 256), inline: false },
      ],
      dedupeKey: `rate_limited:${ip}`,
    });
    return res
      .status(429)
      .set("Retry-After", String(rl.retryAfter))
      .type("text/plain")
      .send(`Too many attempts. Try again in ${rl.retryAfter}s.`);
  }

  // Every POST attempt counts, success or failure.
  recordAttempt(ip);

  const { client_id, redirect_uri, state, code_challenge, password } = req.body;

  if (!client_id || !registeredClients.has(client_id)) return res.status(400).send("Unknown client_id");

  const client = registeredClients.get(client_id);
  if (!client.redirect_uris.includes(redirect_uri)) return res.status(400).send("Invalid redirect_uri");

  if (password !== AUTH_PASSWORD) {
    console.log(`[AUTH-FAIL] ip=${ip} client_id=${client_id}`);
    sendDiscordAlert({
      title: "⚠️ Failed authorize attempt",
      description: `A bad password was submitted to \`POST /oauth/authorize\`.`,
      color: 0xFEE75C, // yellow
      fields: [
        { name: "IP", value: `\`${ip}\``, inline: true },
        { name: "Client ID", value: `\`${client_id}\``, inline: true },
        { name: "User-Agent", value: truncate(ua, 256), inline: false },
      ],
      dedupeKey: `bad_password:${ip}`,
    });
    return res.type("html").send(authPage({ client_id, redirect_uri, state, code_challenge, error: true }));
  }

  const code = generateId(32);
  authCodes.set(code, {
    clientId: client_id,
    codeChallenge: code_challenge,
    redirectUri: redirect_uri,
    expiresAt: Date.now() + AUTH_CODE_TTL,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);
  res.redirect(302, redirectUrl.toString());
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
    accessTokens.set(token, { clientId: client_id, expiresAt: Date.now() + ACCESS_TOKEN_TTL });
    refreshTokens.set(refresh, { clientId: client_id, expiresAt: Date.now() + REFRESH_TOKEN_TTL });
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
    accessTokens.set(newToken, { clientId: client_id, expiresAt: Date.now() + ACCESS_TOKEN_TTL });
    refreshTokens.set(newRefresh, { clientId: client_id, expiresAt: Date.now() + REFRESH_TOKEN_TTL });
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

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const server = createRailwayMcpServer();
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
// Auth page HTML
// ---------------------------------------------------------------------------
function authPage({ client_id, redirect_uri, state, code_challenge, error = false }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize — Railway MCP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 12px; padding: 2rem; max-width: 360px; width: 100%; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
  h1 { font-size: 1.25rem; margin-bottom: .25rem; }
  p { font-size: .875rem; color: #666; margin-bottom: 1.5rem; }
  label { font-size: .875rem; font-weight: 500; display: block; margin-bottom: .5rem; }
  input[type="password"] { width: 100%; padding: .6rem .75rem; border: 1px solid #ccc; border-radius: 8px; font-size: 1rem; margin-bottom: 1rem; }
  button { width: 100%; padding: .65rem; background: #7B61FF; color: #fff; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; }
  button:hover { background: #6B4FE0; }
  .error { color: #c9362b; font-size: .85rem; margin-bottom: 1rem; }
</style>
</head>
<body>
<div class="card">
  <h1>Railway MCP Server</h1>
  <p>Enter your password to authorize access.</p>
  ${error ? '<div class="error">Incorrect password. Please try again.</div>' : ""}
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="${client_id}">
    <input type="hidden" name="redirect_uri" value="${redirect_uri}">
    <input type="hidden" name="state" value="${state || ""}">
    <input type="hidden" name="code_challenge" value="${code_challenge}">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autofocus>
    <button type="submit">Authorize</button>
  </form>
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Railway MCP server listening on port ${PORT}`);
  console.log(`Public URL: ${PUBLIC_URL}`);
  console.log("Auth: OAuth 2.0 with PKCE");
  console.log(
    `Rate limit on POST /oauth/authorize: ${RATE_LIMIT_PER_MINUTE}/min, ${RATE_LIMIT_PER_HOUR}/hr per IP`
  );
  console.log(`Discord alerts: ${DISCORD_WEBHOOK_URL ? "enabled" : "disabled (no DISCORD_WEBHOOK_URL)"}`);
  console.log(`MCP activity alerts: ${MCP_ACTIVITY_ALERTS ? "ON" : "OFF (set MCP_ACTIVITY_ALERTS=true to enable)"}`);
});
