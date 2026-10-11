// Railway Sandbox tools for Railway MCP server.
//
// Provides:
//   - railway-create-sandbox       Create a sandbox (fresh, from a checkpoint, or forked from another),
//                                  optionally on the private network and with public HTTPS ports
//   - railway-sandbox-exec         Run a shell command (or start it in the background) and return output
//   - railway-sandbox-job          Check on / stop a background command started by railway-sandbox-exec
//   - railway-sandbox-write-file   Write a file into a sandbox (any size; chunked server-side)
//   - railway-sandbox-read-file    Read a file (or a byte range of one) from a sandbox
//   - railway-sandbox-checkpoint   Save, list or delete named disk snapshots to start sandboxes from
//   - railway-list-sandboxes       List sandboxes in an environment
//   - railway-destroy-sandbox      Destroy a sandbox
//   - railway-create-readonly-db-user
//                                  One-time setup: a read-only Postgres user (plus its own scratch
//                                  schema) whose connection string is saved as a service variable
//
// Why this exists: a sandbox created with networkIsolation PRIVATE joins the
// environment's private network, so it can reach services like
// postgres.railway.internal without the database ever getting a public
// address. Combined with exec, that lets an agent query a private database,
// run a branch of an app against real data, and check it in a browser.
//
// These use the same GraphQL operations as Railway's own SDK (`railway` on
// npm): sandboxCreate, sandbox, sandboxes, sandboxExec, sandboxDestroy,
// sandboxCheckpointCreate/Delete, sandboxCheckpoints. Exec is the
// single-request form (the SDK's execHttp): no streaming or stdin, and Railway
// truncates each output stream at about 16 KB. File transfer and background
// jobs are built on top of it here, so they need no websocket.

import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { gql } from "graphql-request";

function toolResponse(text) {
  return { content: [{ type: "text", text }] };
}

const SANDBOX_FIELDS = `
  id
  status
  networkIsolation
  environmentId
  region
  idleTimeoutMinutes
  createdAt
  domains { domain port }
`;

const TERMINAL = new Set(["FAILED", "DESTROYED", "DESTROYING"]);
const READY_TIMEOUT_MS = 3 * 60 * 1000;
const POLL_MS = 2000;

// A single exec request fails somewhere above ~20 KB of command text, so files
// go up in base64 chunks well under that.
const WRITE_CHUNK_CHARS = 12000;
// Output streams are truncated at ~16 KB; base64 grows data by 4/3.
const READ_MAX_BYTES = 11000;
const JOB_DIR = "/tmp/.mcp-jobs";
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

function describe(s) {
  const gone = TERMINAL.has(s.status);
  const domains = (s.domains || []).map((d) => `https://${d.domain} → port ${d.port}`);
  return (
    `**${s.id}**: ${s.status}` +
    // A destroyed sandbox no longer reports its real network mode, so don't show one.
    (gone ? "" : `\n  network: ${s.networkIsolation === "PRIVATE" ? "private (can reach *.railway.internal)" : "isolated (internet only)"}`) +
    `${s.region && !gone ? ` | region: ${s.region}` : ""}` +
    `${s.idleTimeoutMinutes != null && !gone ? ` | idle timeout: ${s.idleTimeoutMinutes} min` : ""}` +
    `${s.createdAt ? ` | created: ${s.createdAt}` : ""}` +
    (domains.length && !gone ? `\n  public: ${domains.join(", ")}` : "")
  );
}

const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`; // single-quote for the shell

export function registerSandboxTools(server, deps) {
  const { gqlRequest, resolveEnvironmentId } = deps;

  async function getSandbox(environmentId, id) {
    const data = await gqlRequest(
      gql`
        query ($environmentId: String!, $id: String!) {
          sandbox(environmentId: $environmentId, id: $id) {
            ${SANDBOX_FIELDS}
          }
        }
      `,
      { environmentId, id }
    );
    return data.sandbox;
  }

  async function exec(environmentId, id, command, timeoutSec = 120) {
    const data = await gqlRequest(
      gql`
        mutation ($environmentId: String!, $id: String!, $command: String!, $timeoutSec: Int) {
          sandboxExec(environmentId: $environmentId, id: $id, command: $command, timeoutSec: $timeoutSec) {
            exitCode
            stdout
            stderr
            truncated
            timedOut
          }
        }
      `,
      { environmentId, id, command, timeoutSec }
    );
    return data.sandboxExec || {};
  }

  // Exec that must succeed; throws with stderr otherwise.
  async function run(environmentId, id, command, timeoutSec) {
    const r = await exec(environmentId, id, command, timeoutSec);
    if (r.exitCode !== 0 || r.timedOut) {
      const why = r.timedOut ? "timed out" : `exit ${r.exitCode}`;
      throw new Error(`${why}: ${(r.stderr || r.stdout || "").trim().slice(0, 600)}`);
    }
    return r;
  }

  async function createAndWait(input) {
    const created = await gqlRequest(
      gql`
        mutation ($input: SandboxCreateInput!) {
          sandboxCreate(input: $input) {
            ${SANDBOX_FIELDS}
          }
        }
      `,
      { input }
    );
    let sb = created.sandboxCreate;
    const deadline = Date.now() + READY_TIMEOUT_MS;
    while (sb.status !== "RUNNING" && !TERMINAL.has(sb.status) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      sb = (await getSandbox(input.environmentId, sb.id)) || sb;
    }
    return sb;
  }

  async function destroy(environmentId, id) {
    await gqlRequest(
      gql`
        mutation ($id: String!, $environmentId: String!) {
          sandboxDestroy(id: $id, environmentId: $environmentId) {
            id
          }
        }
      `,
      { id, environmentId }
    );
  }

  async function writeFile(environmentId, id, path, buf) {
    const b64 = buf.toString("base64");
    const tmp = `/tmp/.mcp-upload-${randomBytes(6).toString("hex")}`;
    await run(environmentId, id, `mkdir -p "$(dirname ${sq(path)})" && : > ${tmp}`);
    for (let i = 0; i < b64.length; i += WRITE_CHUNK_CHARS) {
      await run(environmentId, id, `printf %s ${sq(b64.slice(i, i + WRITE_CHUNK_CHARS))} >> ${tmp}`);
    }
    const r = await run(
      environmentId,
      id,
      `base64 -d ${tmp} > ${sq(path)} && rm -f ${tmp} && sha256sum ${sq(path)} | cut -d' ' -f1`
    );
    const want = createHash("sha256").update(buf).digest("hex");
    const got = (r.stdout || "").trim();
    if (got !== want) throw new Error(`checksum mismatch after upload (expected ${want}, got ${got})`);
    return Math.max(1, Math.ceil(b64.length / WRITE_CHUNK_CHARS));
  }

  const envFields = {
    projectId: z.string().describe("The project ID"),
    environmentId: z
      .string()
      .optional()
      .describe("The environment ID (defaults to the project's production environment)"),
  };

  // -- railway-create-sandbox --
  server.tool(
    "railway-create-sandbox",
    "Create a Railway Sandbox (a disposable Linux machine) in a project's environment and wait until it's running. " +
      "Start it fresh, from a saved checkpoint (checkpoint: name, see railway-sandbox-checkpoint), or as a copy of a running sandbox's files (forkFrom: sandboxId). " +
      "With privateNetwork=true (the default) it joins the environment's private network, so it can reach services such as postgres.railway.internal while they stay private. " +
      "Pass variables to expose values to every command, including references like {\"DATABASE_URL\": \"${{Postgres.DATABASE_URL}}\"}, which Railway resolves server-side so secrets never pass through the chat. " +
      "publicPorts gives each listed port its own public HTTPS address (a server must listen on 0.0.0.0); anyone with the address can reach it until the sandbox is destroyed, so only use it for things that are safe to expose, and prefer short idle timeouts. " +
      "It's destroyed automatically after idleTimeoutMinutes of inactivity. environmentId defaults to the project's production environment.",
    {
      ...envFields,
      privateNetwork: z
        .boolean()
        .optional()
        .describe("Join the environment's private network (default true). false = internet access only."),
      idleTimeoutMinutes: z
        .number()
        .int()
        .optional()
        .describe("Destroy after this many idle minutes (default 30; Hobby/Pro allow 1-120)"),
      variables: z
        .record(z.string())
        .optional()
        .describe('Environment variables for every command. Railway references like "${{Postgres.DATABASE_URL}}" are resolved at creation.'),
      checkpoint: z
        .string()
        .optional()
        .describe("Start from this saved checkpoint (by name) instead of the default image"),
      forkFrom: z
        .string()
        .optional()
        .describe("Start as a copy of this running sandbox's files (sandbox ID). Processes aren't copied."),
      publicPorts: z
        .array(z.number().int().min(1).max(65535))
        .max(10)
        .optional()
        .describe("Ports to publish at public HTTPS addresses (requires the private network). Off unless given."),
      region: z.string().optional().describe("Region, e.g. us-east4-eqdc4a (default us-west2; forks use their source's region)"),
    },
    async ({ projectId, environmentId, privateNetwork, idleTimeoutMinutes, variables, checkpoint, forkFrom, publicPorts, region }) => {
      try {
        if (checkpoint && forkFrom) return toolResponse("Use either checkpoint or forkFrom, not both.");
        if (publicPorts?.length && privateNetwork === false)
          return toolResponse("publicPorts needs the private network (privateNetwork: true).");
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const input = {
          environmentId: envId,
          networkIsolation: privateNetwork === false ? "ISOLATED" : "PRIVATE",
          idleTimeoutMinutes: idleTimeoutMinutes ?? 30,
        };
        if (variables && Object.keys(variables).length) input.variables = variables;
        if (checkpoint) input.template = { name: checkpoint };
        if (forkFrom) input.sourceSandboxId = forkFrom;
        if (publicPorts?.length) input.publicDomains = [...new Set(publicPorts)].map((port) => ({ port }));
        if (region && !forkFrom) input.region = region;

        const sb = await createAndWait(input);
        const vars = variables ? Object.keys(variables) : [];
        if (sb.status !== "RUNNING") {
          return toolResponse(
            `Sandbox ${sb.id} was created but isn't running (status: ${sb.status}). ` +
              (TERMINAL.has(sb.status) ? "It failed to start." : "It may still be starting; check with railway-list-sandboxes.")
          );
        }
        const from = checkpoint ? ` from checkpoint "${checkpoint}"` : forkFrom ? ` as a fork of ${forkFrom}` : "";
        return toolResponse(
          `Sandbox running${from}.\n\n${describe(sb)}\n` +
            (vars.length ? `  variables: ${vars.join(", ")}\n` : "") +
            `\nRun commands with railway-sandbox-exec (sandboxId: ${sb.id}, environmentId: ${envId}).`
        );
      } catch (error) {
        return toolResponse(`Failed to create sandbox: ${error.message}`);
      }
    }
  );

  // -- railway-sandbox-exec --
  server.tool(
    "railway-sandbox-exec",
    "Run a shell command in a Railway Sandbox and return its exit code, stdout and stderr. The command runs in a shell, so pipes and && work, and the sandbox's variables (e.g. $DATABASE_URL) are set. " +
      "Single request: no streaming or stdin, and Railway truncates each output stream at about 16 KB, so keep output small (LIMIT queries, summarize). " +
      "For anything long-running (a server, a build, a job over ~1-2 minutes), set background: true with a name; it returns at once and you check on it with railway-sandbox-job. " +
      "To put files in or get them out, use railway-sandbox-write-file / railway-sandbox-read-file rather than pasting them into a command. environmentId defaults to the project's production environment.",
    {
      ...envFields,
      sandboxId: z.string().describe("The sandbox ID (from railway-create-sandbox or railway-list-sandboxes)"),
      command: z.string().describe("Shell command to run"),
      timeoutSec: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Kill the command after this many seconds (default 120). Ignored with background: true."),
      background: z
        .boolean()
        .optional()
        .describe("Start the command in the background and return immediately (default false)"),
      name: z
        .string()
        .regex(NAME_RE)
        .optional()
        .describe("Job name for a background command (letters, digits, . _ -); used with railway-sandbox-job"),
    },
    async ({ projectId, environmentId, sandboxId, command, timeoutSec, background, name }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        if (background) {
          const job = name || `job-${randomBytes(3).toString("hex")}`;
          const script = Buffer.from(command).toString("base64");
          const base = `${JOB_DIR}/${job}`;
          // The command is stored as a script (no quoting issues), then run detached with its
          // output and exit code captured to files that railway-sandbox-job reads back.
          const launch =
            `mkdir -p ${JOB_DIR} && if [ -f ${base}.pid ] && kill -0 "$(cat ${base}.pid)" 2>/dev/null; then echo "already running" >&2; exit 3; fi; ` +
            `rm -f ${base}.exit; echo ${sq(script)} | base64 -d > ${base}.sh || exit 5; ` +
            // Only the setsid command is backgrounded (not an && chain), so $! is the job's own
            // session/group leader: stop can signal the whole group, and this exec returns at once.
            `setsid nohup bash -c 'bash -l ${base}.sh > ${base}.log 2>&1; echo $? > ${base}.exit' < /dev/null > /dev/null 2>&1 &\n` +
            `echo $! > ${base}.pid; sleep 1; tail -c 2000 ${base}.log 2>/dev/null; exit 0`;
          const r = await exec(envId, sandboxId, launch, 30);
          if (r.exitCode === 3) return toolResponse(`A job named "${job}" is already running. Stop it first or use another name.`);
          if (r.exitCode !== 0) return toolResponse(`Failed to start background job: ${(r.stderr || "").trim()}`);
          return toolResponse(
            `Started background job "${job}".\n` +
              (r.stdout ? `\nFirst output:\n\`\`\`\n${r.stdout}\n\`\`\`\n` : "") +
              `\nCheck on it with railway-sandbox-job (sandboxId: ${sandboxId}, name: ${job}).`
          );
        }
        const r = await exec(envId, sandboxId, command, timeoutSec ?? 120);
        const notes = [];
        if (r.timedOut) notes.push("timed out — for long work use background: true");
        if (r.truncated) notes.push("output truncated (~16 KB per stream)");
        let text = `Exit code: ${r.exitCode}${notes.length ? ` (${notes.join("; ")})` : ""}\n`;
        if (r.stdout) text += `\nstdout:\n\`\`\`\n${r.stdout}\n\`\`\`\n`;
        if (r.stderr) text += `\nstderr:\n\`\`\`\n${r.stderr}\n\`\`\`\n`;
        if (!r.stdout && !r.stderr) text += "\n(no output)";
        return toolResponse(text);
      } catch (error) {
        return toolResponse(`Failed to run command: ${error.message}`);
      }
    }
  );

  // -- railway-sandbox-job --
  server.tool(
    "railway-sandbox-job",
    "Check on or stop a background command started with railway-sandbox-exec (background: true). status returns whether it's running, its exit code once finished, and the end of its output; stop ends it. Omit name to list all jobs in the sandbox.",
    {
      ...envFields,
      sandboxId: z.string().describe("The sandbox ID"),
      name: z.string().regex(NAME_RE).optional().describe("Job name (omit to list jobs)"),
      action: z.enum(["status", "stop"]).optional().describe("status (default) or stop"),
      tailBytes: z.number().int().min(0).max(14000).optional().describe("How much of the end of the log to return (default 3000 bytes)"),
    },
    async ({ projectId, environmentId, sandboxId, name, action, tailBytes }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        if (!name) {
          const r = await exec(
            envId,
            sandboxId,
            `cd ${JOB_DIR} 2>/dev/null || exit 0; for p in *.pid; do [ -e "$p" ] || continue; n=\${p%.pid}; ` +
              `if [ -f "$n.exit" ]; then e=$(cat "$n.exit"); case "$e" in ''|*[!0-9]*) echo "$n: stopped";; *) echo "$n: finished (exit $e)";; esac; ` +
              `elif kill -0 "$(cat "$p")" 2>/dev/null; then echo "$n: running"; else echo "$n: stopped"; fi; done`,
            30
          );
          return toolResponse((r.stdout || "").trim() ? `Jobs:\n${r.stdout.trim()}` : "No background jobs in this sandbox.");
        }
        const base = `${JOB_DIR}/${name}`;
        if (action === "stop") {
          const r = await exec(
            envId,
            sandboxId,
            `[ -f ${base}.pid ] || { echo "no such job" >&2; exit 4; }; P=$(cat ${base}.pid); ` +
              `kill -TERM -- -"$P" 2>/dev/null || kill -TERM "$P" 2>/dev/null; sleep 1; ` +
              `kill -0 "$P" 2>/dev/null && { kill -KILL -- -"$P" 2>/dev/null || kill -KILL "$P" 2>/dev/null; }; ` +
              `[ -f ${base}.exit ] || echo stopped > ${base}.exit; echo ok`,
            30
          );
          if (r.exitCode === 4) return toolResponse(`No job named "${name}" in this sandbox.`);
          return toolResponse(`Stopped job "${name}".`);
        }
        const tail = tailBytes ?? 3000;
        const r = await exec(
          envId,
          sandboxId,
          `[ -f ${base}.pid ] || { echo "no such job" >&2; exit 4; }; ` +
            `if [ -f ${base}.exit ]; then echo "STATE finished $(cat ${base}.exit)"; ` +
            `elif kill -0 "$(cat ${base}.pid)" 2>/dev/null; then echo "STATE running"; else echo "STATE stopped"; fi; ` +
            `echo "SIZE $(stat -c %s ${base}.log 2>/dev/null || echo 0)"; echo ---; tail -c ${tail} ${base}.log 2>/dev/null; exit 0`,
          30
        );
        if (r.exitCode === 4) return toolResponse(`No job named "${name}" in this sandbox.`);
        const out = r.stdout || "";
        const cut = out.indexOf("\n---\n");
        const head = cut >= 0 ? out.slice(0, cut) : out;
        const log = cut >= 0 ? out.slice(cut + 5) : "";
        const state = (head.match(/STATE (.*)/) || [])[1] || "unknown";
        const size = Number((head.match(/SIZE (\d+)/) || [])[1] || 0);
        const code = state.startsWith("finished") ? state.split(" ")[1] : null;
        const label = code === null ? state : /^\d+$/.test(code) ? `finished with exit code ${code}` : "stopped";
        return toolResponse(
          `Job "${name}": ${label}. Log is ${size} bytes${size > tail ? ` (showing the last ${tail})` : ""}.\n` +
            (log.trim() ? `\n\`\`\`\n${log}\n\`\`\`` : "\n(no output yet)")
        );
      } catch (error) {
        return toolResponse(`Failed to check job: ${error.message}`);
      }
    }
  );

  // -- railway-sandbox-write-file --
  server.tool(
    "railway-sandbox-write-file",
    "Write a file into a Railway Sandbox, creating parent directories. Any size: it's sent in chunks and checked with a SHA-256 checksum. Use this instead of pasting file contents into railway-sandbox-exec. Set base64: true to send binary content.",
    {
      ...envFields,
      sandboxId: z.string().describe("The sandbox ID"),
      path: z.string().describe("Absolute path in the sandbox, e.g. /root/app/views.py"),
      content: z.string().describe("The file contents (text, or base64 when base64 is true)"),
      base64: z.boolean().optional().describe("content is base64-encoded binary (default false)"),
    },
    async ({ projectId, environmentId, sandboxId, path, content, base64 }) => {
      try {
        if (!path.startsWith("/")) return toolResponse("path must be absolute (start with /).");
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const buf = base64 ? Buffer.from(content, "base64") : Buffer.from(content, "utf8");
        const chunks = await writeFile(envId, sandboxId, path, buf);
        return toolResponse(
          `Wrote ${buf.length} bytes to ${path} (${chunks} chunk${chunks === 1 ? "" : "s"}, checksum verified).`
        );
      } catch (error) {
        return toolResponse(`Failed to write file: ${error.message}`);
      }
    }
  );

  // -- railway-sandbox-read-file --
  server.tool(
    "railway-sandbox-read-file",
    `Read a file from a Railway Sandbox. Returns up to ${READ_MAX_BYTES} bytes per call; use offset to page through larger files. Text is returned as-is; set base64: true for binary files.`,
    {
      ...envFields,
      sandboxId: z.string().describe("The sandbox ID"),
      path: z.string().describe("Absolute path in the sandbox"),
      offset: z.number().int().min(0).optional().describe("Byte offset to start from (default 0)"),
      length: z.number().int().min(1).max(READ_MAX_BYTES).optional().describe(`Bytes to read (default and max ${READ_MAX_BYTES})`),
      base64: z.boolean().optional().describe("Return the bytes base64-encoded (default false)"),
    },
    async ({ projectId, environmentId, sandboxId, path, offset, length, base64 }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const off = offset ?? 0;
        const len = length ?? READ_MAX_BYTES;
        const r = await exec(
          envId,
          sandboxId,
          `[ -f ${sq(path)} ] || { echo "not a file" >&2; exit 4; }; stat -c %s ${sq(path)}; ` +
            `tail -c +${off + 1} ${sq(path)} | head -c ${len} | base64 -w0`,
          60
        );
        if (r.exitCode === 4) return toolResponse(`${path} doesn't exist or isn't a regular file.`);
        if (r.exitCode !== 0) return toolResponse(`Failed to read file: ${(r.stderr || "").trim()}`);
        const nl = (r.stdout || "").indexOf("\n");
        const size = Number((r.stdout || "").slice(0, nl)) || 0;
        const bytes = Buffer.from((r.stdout || "").slice(nl + 1).trim(), "base64");
        const end = off + bytes.length;
        const more = end < size ? ` More remains: call again with offset ${end}.` : "";
        const header = `${path}: ${size} bytes total; showing bytes ${off}-${end}.${more}`;
        if (base64) return toolResponse(`${header}\n\n${bytes.toString("base64")}`);
        return toolResponse(`${header}\n\n\`\`\`\n${bytes.toString("utf8")}\n\`\`\``);
      } catch (error) {
        return toolResponse(`Failed to read file: ${error.message}`);
      }
    }
  );

  // -- railway-sandbox-checkpoint --
  server.tool(
    "railway-sandbox-checkpoint",
    "Manage checkpoints: named snapshots of a sandbox's disk, stored in the environment, that new sandboxes can start from (railway-create-sandbox with checkpoint: name). " +
      "Use them to skip setup: install tools and dependencies once, save, and start from the checkpoint next time. Running processes and memory aren't saved. " +
      "action: save (needs sandboxId and name; reusing a name replaces it), list, or delete (by name).",
    {
      ...envFields,
      action: z.enum(["save", "list", "delete"]).describe("save, list or delete"),
      name: z.string().regex(NAME_RE).optional().describe("Checkpoint name (for save and delete)"),
      sandboxId: z.string().optional().describe("The running sandbox to save (for save)"),
    },
    async ({ projectId, environmentId, action, name, sandboxId }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const list = async () =>
          (
            await gqlRequest(
              gql`
                query ($environmentId: String!) {
                  sandboxCheckpoints(environmentId: $environmentId) {
                    id
                    key
                    createdAt
                  }
                }
              `,
              { environmentId: envId }
            )
          ).sandboxCheckpoints || [];
        if (action === "list") {
          // Names that are 64-char hex hashes belong to template builds, not saved checkpoints.
          const cps = (await list()).filter((c) => !/^[0-9a-f]{64}$/.test(c.key));
          if (!cps.length) return toolResponse("No checkpoints in this environment.");
          return toolResponse(`Checkpoints:\n${cps.map((c) => `- **${c.key}** (saved ${c.createdAt})`).join("\n")}`);
        }
        if (!name) return toolResponse(`${action} needs a checkpoint name.`);
        if (action === "save") {
          if (!sandboxId) return toolResponse("save needs the sandboxId to snapshot.");
          const data = await gqlRequest(
            gql`
              mutation ($environmentId: String!, $name: String!, $sandboxId: String!) {
                sandboxCheckpointCreate(environmentId: $environmentId, name: $name, sandboxId: $sandboxId) {
                  id
                  key
                  createdAt
                }
              }
            `,
            { environmentId: envId, name, sandboxId }
          );
          return toolResponse(
            `Saved checkpoint "${data.sandboxCheckpointCreate.key}". Start a sandbox from it with railway-create-sandbox (checkpoint: "${name}").`
          );
        }
        const cp = (await list()).find((c) => c.key === name);
        if (!cp) return toolResponse(`No checkpoint named "${name}".`);
        await gqlRequest(
          gql`
            mutation ($environmentId: String!, $id: ID!) {
              sandboxCheckpointDelete(environmentId: $environmentId, id: $id)
            }
          `,
          { environmentId: envId, id: cp.id }
        );
        return toolResponse(`Deleted checkpoint "${name}" and its disk snapshot.`);
      } catch (error) {
        return toolResponse(`Failed to ${action} checkpoint: ${error.message}`);
      }
    }
  );

  // -- railway-list-sandboxes --
  server.tool(
    "railway-list-sandboxes",
    "List the Railway Sandboxes in a project's environment with their status, network mode and any public addresses. environmentId defaults to the project's production environment.",
    { ...envFields },
    async ({ projectId, environmentId }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const data = await gqlRequest(
          gql`
            query ($environmentId: String!, $first: Int) {
              sandboxes(environmentId: $environmentId, first: $first) {
                edges {
                  node {
                    ${SANDBOX_FIELDS}
                  }
                }
              }
            }
          `,
          { environmentId: envId, first: 50 }
        );
        const list = (data.sandboxes?.edges || []).map((e) => e.node);
        if (!list.length) return toolResponse("No sandboxes in this environment.");
        return toolResponse(`Found ${list.length} sandbox(es):\n\n${list.map(describe).join("\n")}`);
      } catch (error) {
        return toolResponse(`Failed to list sandboxes: ${error.message}`);
      }
    }
  );

  // -- railway-destroy-sandbox --
  server.tool(
    "railway-destroy-sandbox",
    "Destroy a Railway Sandbox now instead of waiting for its idle timeout. Anything stored in it is lost (save a checkpoint first to keep its files). environmentId defaults to the project's production environment.",
    {
      ...envFields,
      sandboxId: z.string().describe("The sandbox ID"),
    },
    async ({ projectId, environmentId, sandboxId }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        await destroy(envId, sandboxId);
        // The mutation returns the status from before the destroy, so re-read it.
        let sb = null;
        const deadline = Date.now() + 20000;
        do {
          sb = await getSandbox(envId, sandboxId).catch(() => null);
          if (!sb || TERMINAL.has(sb.status)) break;
          await new Promise((r) => setTimeout(r, 1500));
        } while (Date.now() < deadline);
        if (!sb || sb.status === "DESTROYED") return toolResponse(`Sandbox ${sandboxId} is destroyed.`);
        if (sb.status === "DESTROYING") return toolResponse(`Sandbox ${sandboxId} is being destroyed.`);
        return toolResponse(
          `Asked Railway to destroy sandbox ${sandboxId}; it still reports ${sb.status}. Check again with railway-list-sandboxes.`
        );
      } catch (error) {
        return toolResponse(`Failed to destroy sandbox: ${error.message}`);
      }
    }
  );

  // -- railway-create-readonly-db-user --
  // Everything secret stays server-side: the admin connection string is a Railway
  // reference resolved inside the sandbox, the new password is generated here and
  // only ever sent to Railway's API, and the result is stored as a service variable.
  const RO_SCRIPT = String.raw`
const { Client } = require("pg");
const role = process.env.RO_ROLE, scratch = process.env.RO_SCRATCH;
const exclude = JSON.parse(process.env.RO_EXCLUDE || "[]");
const q = (c, s, p) => c.query(s, p);
const ident = (s) => '"' + String(s).replace(/"/g, '""') + '"';
(async () => {
  const out = { steps: [] };
  const admin = new Client({ connectionString: process.env.ADMIN_URL });
  await admin.connect();
  const db = (await q(admin, "select current_database() d, current_user u, current_setting('server_version') v")).rows[0];
  out.database = db.d; out.version = "PostgreSQL " + db.v.split(" ")[0];
  const exists = (await q(admin, "select 1 from pg_roles where rolname=$1", [role])).rowCount > 0;
  const fmt = async (sql, args) => (await q(admin, "select format(" + sql + ") s", args)).rows[0].s;
  if (!exists) await q(admin, await fmt("'CREATE ROLE %I LOGIN', $1::text", [role]));
  await q(admin, await fmt("'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', $1::text, $2::text", [role, process.env.RO_PW]));
  out.steps.push(exists ? "updated existing user and reset its password" : "created user");
  await q(admin, await fmt("'GRANT CONNECT ON DATABASE %I TO %I', $1::text, $2::text", [db.d, role]));
  await q(admin, await fmt("'GRANT USAGE ON SCHEMA public TO %I', $1::text", [role]));
  await q(admin, await fmt("'GRANT SELECT ON ALL TABLES IN SCHEMA public TO %I', $1::text", [role]));
  await q(admin, await fmt("'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO %I', $1::text", [role]));
  out.steps.push("read access to all current and future tables in public");
  out.excluded = [];
  for (const t of exclude) {
    const ok = (await q(admin, "select to_regclass($1) is not null r", ["public." + ident(t)])).rows[0].r;
    if (!ok) { out.steps.push("no table " + t + " to hide"); continue; }
    await q(admin, await fmt("'REVOKE ALL ON TABLE public.%I FROM %I', $1::text, $2::text", [t, role]));
    out.excluded.push(t);
  }
  await q(admin, await fmt("'CREATE SCHEMA IF NOT EXISTS %I AUTHORIZATION %I', $1::text, $2::text", [scratch, role]));
  await q(admin, await fmt("'ALTER ROLE %I SET search_path = %I, public', $1::text, $2::text", [role, scratch]));
  out.steps.push("its own scratch schema " + scratch + ", first on its search path");
  await admin.end();

  // Prove it: connect as the new user and try what it should and shouldn't be able to do.
  const u = new URL(process.env.ADMIN_URL);
  u.username = role; u.password = process.env.RO_PW;
  const ro = new Client({ connectionString: u.toString() });
  await ro.connect();
  const check = {};
  const tables = (await q(ro, "select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE' order by 1")).rows.map(r => r.table_name);
  const readable = tables.find(t => !out.excluded.includes(t));
  if (readable) {
    try { await q(ro, "select 1 from public." + ident(readable) + " limit 1"); check.read = "ok (" + readable + ")"; }
    catch (e) { check.read = "FAILED: " + e.message; }
    try { await q(ro, "begin"); await q(ro, "delete from public." + ident(readable)); check.write_public = "ALLOWED (unexpected)"; }
    catch (e) { check.write_public = "blocked"; }
    finally { await q(ro, "rollback").catch(() => {}); }
  }
  for (const t of out.excluded) {
    try { await q(ro, "select 1 from public." + ident(t) + " limit 1"); check["read_" + t] = "ALLOWED (unexpected)"; }
    catch (e) { check["read_" + t] = "blocked"; }
  }
  try { await q(ro, "create table _ro_probe(x int)"); await q(ro, "drop table _ro_probe"); check.scratch_write = "ok"; }
  catch (e) { check.scratch_write = "FAILED: " + e.message; }
  check.can_create_in_public = (await q(ro, "select has_schema_privilege(current_user,'public','CREATE') c")).rows[0].c;
  await ro.end();
  out.checks = check; out.tables = tables.length;
  console.log("RESULT " + JSON.stringify(out));
})().catch(e => { console.error("ERROR " + e.message); process.exit(1); });
`;

  server.tool(
    "railway-create-readonly-db-user",
    "One-time setup for safer database work: create (or refresh) a read-only Postgres user in a project's database, plus a scratch schema it owns for throwaway tables, and save its connection string as a variable on the Postgres service (default DATABASE_URL_READONLY). " +
      "Sandboxes for analysis or app previews can then use {\"DATABASE_URL\": \"${{Postgres.DATABASE_URL_READONLY}}\"} so they can read real data but can't change it. excludeTables hides tables entirely (e.g. ones holding API tokens). " +
      "The password is generated server-side and never appears in the chat; the Postgres service is not redeployed. Runs inside a temporary sandbox on the private network, then destroys it, and reports checks proving what the user can and can't do.",
    {
      ...envFields,
      postgresServiceId: z.string().describe("The Postgres service ID"),
      roleName: z.string().regex(/^[a-z_][a-z0-9_]{0,40}$/).optional().describe("Database user name (default analyst)"),
      excludeTables: z
        .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,62}$/))
        .optional()
        .describe("Tables in public the user must not see"),
      scratchSchema: z.string().regex(/^[a-z_][a-z0-9_]{0,40}$/).optional().describe("Schema the user owns for scratch tables (default scratch)"),
      variableName: z
        .string()
        .regex(/^[A-Z_][A-Z0-9_]{0,60}$/)
        .optional()
        .describe("Variable to store the connection string in (default DATABASE_URL_READONLY)"),
    },
    async ({ projectId, environmentId, postgresServiceId, roleName, excludeTables, scratchSchema, variableName }) => {
      const role = roleName || "analyst";
      const scratch = scratchSchema || "scratch";
      const varName = variableName || "DATABASE_URL_READONLY";
      let envId, sandboxId;
      try {
        envId = await resolveEnvironmentId(projectId, environmentId);
        const svc = await gqlRequest(
          gql`
            query ($id: String!) {
              service(id: $id) {
                name
              }
            }
          `,
          { id: postgresServiceId }
        );
        const svcName = svc.service?.name;
        if (!svcName) return toolResponse("Couldn't find that Postgres service.");
        if (!/^[A-Za-z0-9_-]+$/.test(svcName))
          return toolResponse(`The service name "${svcName}" can't be used in a variable reference.`);
        const pw = randomBytes(24).toString("base64url");

        const sb = await createAndWait({
          environmentId: envId,
          networkIsolation: "PRIVATE",
          idleTimeoutMinutes: 10,
          variables: {
            ADMIN_URL: `\${{${svcName}.DATABASE_URL}}`,
            RO_PW: pw,
            RO_ROLE: role,
            RO_SCRATCH: scratch,
            RO_EXCLUDE: JSON.stringify(excludeTables || []),
          },
        });
        sandboxId = sb.id;
        if (sb.status !== "RUNNING") throw new Error(`setup sandbox didn't start (status ${sb.status})`);
        await writeFile(envId, sandboxId, "/tmp/ro-setup/setup.js", Buffer.from(RO_SCRIPT));
        await run(envId, sandboxId, "cd /tmp/ro-setup && npm init -y >/dev/null && npm install --silent pg@8 >/dev/null 2>&1", 180);
        const r = await exec(envId, sandboxId, "cd /tmp/ro-setup && node setup.js", 120);
        const line = (r.stdout || "").split("\n").find((l) => l.startsWith("RESULT "));
        if (r.exitCode !== 0 || !line) {
          throw new Error(
            ((r.stderr || "") + (r.stdout || "")).replace(/postgres(ql)?:\/\/\S*/g, "[url]").trim().slice(0, 600)
          );
        }
        const res = JSON.parse(line.slice(7));

        // Same host and database as the admin URL, built from the service's own variables.
        const value = `postgresql://${role}:${pw}@\${{RAILWAY_PRIVATE_DOMAIN}}:5432/\${{PGDATABASE}}`;
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
              serviceId: postgresServiceId,
              variables: { [varName]: value },
              skipDeploys: true,
            },
          }
        );

        const c = res.checks || {};
        const lines = [
          `Read-only user **${role}** is ready in database ${res.database} (${res.version}); it can read ${res.tables} table${res.tables === 1 ? "" : "s"} in public.`,
          "",
          ...res.steps.map((s) => `- ${s}`),
          res.excluded?.length ? `- hidden entirely: ${res.excluded.join(", ")}` : null,
          `- connection string saved as ${varName} on ${svcName} (no redeploy)`,
          "",
          "Checks, connected as the new user:",
          c.read ? `- read a table: ${c.read}` : null,
          c.write_public ? `- delete rows in a real table: ${c.write_public}` : null,
          ...Object.entries(c)
            .filter(([k]) => k.startsWith("read_"))
            .map(([k, v]) => `- read ${k.slice(5)}: ${v}`),
          `- create a table in ${scratch}: ${c.scratch_write}`,
          c.can_create_in_public
            ? "- note: it can still create new tables in public (the Postgres default before v15), but can't change existing ones"
            : "- create tables in public: blocked",
          "",
          `Use it in a sandbox with variables {"DATABASE_URL": "\${{${svcName}.${varName}}}"}.`,
        ].filter((l) => l !== null);
        return toolResponse(lines.join("\n"));
      } catch (error) {
        return toolResponse(`Failed to set up the read-only user: ${error.message}`);
      } finally {
        if (sandboxId) await destroy(envId, sandboxId).catch(() => {});
      }
    }
  );
}
