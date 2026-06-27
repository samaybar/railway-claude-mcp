import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import express from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { Octokit } from "@octokit/rest";

const PORT = parseInt(process.env.PORT || "3000", 10);
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
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

// --- Login with Railway (OAuth 2.0 / OIDC) — used ONLY to authenticate the
// human connecting from Claude. The GitHub API itself is called with the
// static GITHUB_TOKEN below. ---
const RAILWAY_OIDC = {
  authorize: "https://backboard.railway.com/oauth/auth",
  token: "https://backboard.railway.com/oauth/token",
  userinfo: "https://backboard.railway.com/oauth/me",
  register: "https://backboard.railway.com/oauth/register",
};
const RAILWAY_CALLBACK = `${PUBLIC_URL}/oauth/railway/callback`;
// Identity only — no workspace scope needed, since this server doesn't call the
// Railway API.
const RAILWAY_OAUTH_SCOPE = process.env.RAILWAY_OAUTH_SCOPE || "openid email profile";
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

if (!GITHUB_TOKEN) {
  console.error("Error: GITHUB_TOKEN environment variable is required");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// GitHub client
// ---------------------------------------------------------------------------
const octokit = new Octokit({ auth: GITHUB_TOKEN });

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
let railwayClientReg = null;
// Trust-on-first-use owner when ALLOWED_RAILWAY_EMAILS is empty: { sub, email }.
let owner = null;
// In-flight logins: railwayState -> { claude*, railwayVerifier, createdAt }.
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
// Debounce repeated alerts for the same (key, ip) tuple to avoid spam.
// Key is typically the event type, e.g. "bad_password" or "rate_limited".
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
        footer: { text: "github-mcp-server" },
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
  // Drop anything older than one hour; the minute-window is a subset.
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
// Two kinds of alerts:
//   - session-start: on "initialize" method, debounced per-token per hour
//   - destructive-tool: on "tools/call" for write tools, no debounce
// Read-only tools_call and other methods are only logged to console.

const DESTRUCTIVE_TOOLS = new Set([
  "create-repo",
  "create-or-update-file",
  "patch-file",
  "delete-file",
  "create-pull-request",
  "create-branch",
]);

// Map: tokenPrefix -> last session-start-alert timestamp.
// Key is a short hash of the token so we don't keep raw tokens as map keys.
const lastSessionAlertAt = new Map();
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
    case "create-or-update-file":
    case "delete-file":
      return `${a.owner || "?"}/${a.repo || "?"} ${a.path || "?"}${a.branch ? `@${a.branch}` : ""}`;
    case "patch-file":
      return `${a.owner || "?"}/${a.repo || "?"} ${a.path || "?"}${a.branch ? `@${a.branch}` : ""} (patch)`;
    case "create-branch":
      return `${a.owner || "?"}/${a.repo || "?"} new=${a.branch || "?"}${a.from ? ` from=${a.from}` : ""}`;
    case "create-pull-request":
      return `${a.owner || "?"}/${a.repo || "?"} ${a.head || "?"}→${a.base || "?"}: ${truncate(a.title, 80)}`;
    case "create-repo":
      return `${a.owner ? a.owner + "/" : ""}${a.name || "?"}${a.private === false ? " (public)" : " (private)"}`;
    default:
      return "";
  }
}

function logMcpActivity({ req, token, body }) {
  const method = body?.method;
  const ip = req.ip || "unknown";
  const ua = req.headers["user-agent"] || "unknown";

  if (!method) return;

  // Minimal console trace for all activity (useful regardless of alerting state).
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

    sendDiscordAlert({
      title: "🟠 MCP write tool called",
      description: `Tool: \`${toolName}\``,
      color: 0xE67E22, // orange
      fields: [
        ...(summary ? [{ name: "Target", value: truncate(summary, 256), inline: false }] : []),
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

// ---------------------------------------------------------------------------
// MCP Server with GitHub tools
// ---------------------------------------------------------------------------
function createGitHubMcpServer() {
  const server = new McpServer(
    {
      name: "github-mcp-server",
      title: "GitHub MCP Server",
      version: "1.0.0",
    },
    { capabilities: { logging: {} } }
  );

  // -- check-connection --
  server.tool(
    "check-connection",
    "Check GitHub API connectivity and show authenticated user",
    {},
    { title: "Check connection", readOnlyHint: true, openWorldHint: true },
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

  // -- list-repos --
  server.tool(
    "list-repos",
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
    { title: "List repositories", readOnlyHint: true, openWorldHint: true },
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
        return toolResponse(`Failed to list repos: ${error.message}`);
      }
    }
  );

  // -- get-repo --
  server.tool(
    "get-repo",
    "Get details about a specific repository",
    {
      owner: z.string().describe("Repository owner (username or org)"),
      repo: z.string().describe("Repository name"),
    },
    { title: "Get repository", readOnlyHint: true, openWorldHint: true },
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
        return toolResponse(`Failed to get repo: ${error.message}`);
      }
    }
  );

  // -- create-repo --
  server.tool(
    "create-repo",
    "Create a new GitHub repository",
    {
      name: z.string().describe("Repository name"),
      description: z.string().optional().describe("Repository description"),
      private: z.boolean().optional().describe("Make repository private (default: true)"),
      owner: z.string().optional().describe("Org to create repo in (defaults to authenticated user)"),
    },
    { title: "Create repository", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
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

        return toolResponse(
          `Repository created!\n\n` +
            `**${data.full_name}**${data.private ? " (private)" : " (public)"}\n` +
            `${data.description ? `Description: ${data.description}\n` : ""}` +
            `URL: ${data.html_url}\n` +
            `Clone: ${data.clone_url}`
        );
      } catch (error) {
        return toolResponse(`Failed to create repo: ${error.message}`);
      }
    }
  );

  // -- list-branches --
  server.tool(
    "list-branches",
    "List branches in a repository",
    {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    { title: "List branches", readOnlyHint: true, openWorldHint: true },
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
        return toolResponse(`Failed to list branches: ${error.message}`);
      }
    }
  );

  // -- create-branch --
  server.tool(
    "create-branch",
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
        return toolResponse(`Failed to create branch: ${error.message}`);
      }
    }
  );

  // -- get-file --
  server.tool(
    "get-file",
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
        return toolResponse(`Failed to get file: ${error.message}`);
      }
    }
  );

  // -- create-or-update-file --
  server.tool(
    "create-or-update-file",
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
        return toolResponse(`Failed to create/update file: ${error.message}`);
      }
    }
  );

  // -- patch-file --
  server.tool(
    "patch-file",
    "Edit a file by replacing an exact string, sending only the change instead of the whole file. " +
      "Fetches the current file server-side, replaces old_str with new_str (old_str must appear exactly once), " +
      "and commits. Use this for edits to existing files; use create-or-update-file for new files or full rewrites.",
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
              `The file may have changed; re-fetch with get-file and retry.`
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
        return toolResponse(`Failed to patch file: ${error.message}`);
      }
    }
  );

  // -- delete-file --
  server.tool(
    "delete-file",
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
        return toolResponse(`Failed to delete file: ${error.message}`);
      }
    }
  );

  // -- list-pull-requests --
  server.tool(
    "list-pull-requests",
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
        return toolResponse(`Failed to list PRs: ${error.message}`);
      }
    }
  );

  // -- get-pull-request --
  server.tool(
    "get-pull-request",
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
        return toolResponse(`Failed to get PR: ${error.message}`);
      }
    }
  );

  // -- create-pull-request --
  server.tool(
    "create-pull-request",
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
        return toolResponse(`Failed to create PR: ${error.message}`);
      }
    }
  );

  // -- search-code --
  server.tool(
    "search-code",
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

  // -- list-commits --
  server.tool(
    "list-commits",
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
        return toolResponse(`Failed to list commits: ${error.message}`);
      }
    }
  );

  // -- get-diff --
  server.tool(
    "get-diff",
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
        return toolResponse(`Failed to get diff: ${error.message}`);
      }
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Login-with-Railway helpers (authentication only)
// ---------------------------------------------------------------------------
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
  if (railwayClientReg?.client_id && railwayClientReg.redirect === RAILWAY_CALLBACK) return;

  try {
    const res = await fetch(RAILWAY_OIDC.register, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Self-hosted GitHub MCP server",
        redirect_uris: [RAILWAY_CALLBACK],
        grant_types: ["authorization_code"],
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

async function railwayUserinfo(accessToken) {
  const res = await fetch(RAILWAY_OIDC.userinfo, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`Railway userinfo failed (${res.status})`);
  return res.json();
}

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

    const mcpCode = generateId(32);
    authCodes.set(mcpCode, {
      clientId: pend.claudeClientId,
      codeChallenge: pend.claudeCodeChallenge,
      redirectUri: pend.claudeRedirectUri,
      expiresAt: Date.now() + AUTH_CODE_TTL,
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
    const server = createGitHubMcpServer();
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
<title>Access denied - GitHub MCP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 2rem; max-width: 380px; width: 100%; text-align: center; }
  h1 { font-size: 1.25rem; margin-bottom: .5rem; color: #f0f6fc; }
  p { font-size: .9rem; color: #8b949e; line-height: 1.5; }
  code { background: #0d1117; border: 1px solid #30363d; padding: .1rem .3rem; border-radius: 4px; }
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
    console.log(`GitHub MCP server listening on port ${PORT}`);
    console.log(`Public URL: ${PUBLIC_URL}`);
    console.log("Auth: Login with Railway (OAuth 2.0 / OIDC + PKCE)");
    console.log(
      `Railway OAuth client: ${railwayClientReg?.client_id || "NOT REGISTERED — set RAILWAY_OAUTH_CLIENT_ID/SECRET"}`
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
