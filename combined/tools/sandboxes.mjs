// Railway Sandbox tools for Railway MCP server.
//
// Provides:
//   - railway-create-sandbox    Create a sandbox in an environment (optionally on its private network)
//   - railway-sandbox-exec      Run a shell command in a sandbox and return its output
//   - railway-list-sandboxes    List sandboxes in an environment
//   - railway-destroy-sandbox   Destroy a sandbox
//
// Why this exists: a sandbox created with networkIsolation PRIVATE joins the
// environment's private network, so it can reach services like
// postgres.railway.internal without the database ever getting a public
// address. Combined with exec, that lets an agent query a private database.
//
// These are the same GraphQL operations Railway's own SDK (`railway` on npm)
// uses: sandboxCreate, sandbox, sandboxes, sandboxExec, sandboxDestroy. Exec
// here is the single-request form (the SDK's execHttp): no streaming or stdin,
// and Railway truncates each output stream at about 16 KB.

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
`;

const TERMINAL = new Set(["FAILED", "DESTROYED", "DESTROYING"]);
const READY_TIMEOUT_MS = 3 * 60 * 1000;
const POLL_MS = 2000;

function describe(s) {
  return (
    `**${s.id}**: ${s.status}\n` +
    `  network: ${s.networkIsolation === "PRIVATE" ? "private (can reach *.railway.internal)" : "isolated (internet only)"}` +
    `${s.region ? ` | region: ${s.region}` : ""}` +
    `${s.idleTimeoutMinutes != null ? ` | idle timeout: ${s.idleTimeoutMinutes} min` : ""}` +
    `${s.createdAt ? ` | created: ${s.createdAt}` : ""}`
  );
}

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

  // -- railway-create-sandbox --
  server.tool(
    "railway-create-sandbox",
    "Create a Railway Sandbox (a disposable Linux machine) in a project's environment and wait until it's running. With privateNetwork=true (the default) it joins the environment's private network, so it can reach services such as postgres.railway.internal while they stay private. Pass variables to expose values to every command, including references like {\"DATABASE_URL\": \"${{Postgres.DATABASE_URL}}\"}, which Railway resolves server-side so secrets never pass through the chat. Run commands in it with railway-sandbox-exec; it's destroyed automatically after idleTimeoutMinutes of inactivity. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe("The environment ID (defaults to the project's production environment)"),
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
    },
    async ({ projectId, environmentId, privateNetwork, idleTimeoutMinutes, variables }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const input = {
          environmentId: envId,
          networkIsolation: privateNetwork === false ? "ISOLATED" : "PRIVATE",
          idleTimeoutMinutes: idleTimeoutMinutes ?? 30,
        };
        if (variables && Object.keys(variables).length) input.variables = variables;

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
          sb = (await getSandbox(envId, sb.id)) || sb;
        }

        const vars = variables ? Object.keys(variables) : [];
        if (sb.status !== "RUNNING") {
          return toolResponse(
            `Sandbox ${sb.id} was created but isn't running (status: ${sb.status}). ` +
              (TERMINAL.has(sb.status) ? "It failed to start." : "It may still be starting; check with railway-list-sandboxes.")
          );
        }
        return toolResponse(
          `Sandbox running.\n\n${describe(sb)}\n` +
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
    "Run a shell command in a Railway Sandbox and return its exit code, stdout and stderr. The command runs in a shell, so pipes and && work, and the sandbox's variables (e.g. $DATABASE_URL) are set. Single request: no streaming or stdin, and Railway truncates each output stream at about 16 KB, so keep output small (LIMIT queries, summarize). environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe("The environment ID (defaults to the project's production environment)"),
      sandboxId: z.string().describe("The sandbox ID (from railway-create-sandbox or railway-list-sandboxes)"),
      command: z.string().describe("Shell command to run"),
      timeoutSec: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Kill the command after this many seconds (default 120)"),
    },
    async ({ projectId, environmentId, sandboxId, command, timeoutSec }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
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
          { environmentId: envId, id: sandboxId, command, timeoutSec: timeoutSec ?? 120 }
        );
        const r = data.sandboxExec || {};
        const notes = [];
        if (r.timedOut) notes.push("timed out");
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

  // -- railway-list-sandboxes --
  server.tool(
    "railway-list-sandboxes",
    "List the Railway Sandboxes in a project's environment with their status and network mode. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe("The environment ID (defaults to the project's production environment)"),
    },
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
    "Destroy a Railway Sandbox now instead of waiting for its idle timeout. Anything stored in it is lost. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe("The environment ID (defaults to the project's production environment)"),
      sandboxId: z.string().describe("The sandbox ID"),
    },
    async ({ projectId, environmentId, sandboxId }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const data = await gqlRequest(
          gql`
            mutation ($id: String!, $environmentId: String!) {
              sandboxDestroy(id: $id, environmentId: $environmentId) {
                id
                status
              }
            }
          `,
          { id: sandboxId, environmentId: envId }
        );
        return toolResponse(`Sandbox ${data.sandboxDestroy.id} is ${data.sandboxDestroy.status}.`);
      } catch (error) {
        return toolResponse(`Failed to destroy sandbox: ${error.message}`);
      }
    }
  );
}
