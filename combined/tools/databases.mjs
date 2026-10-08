// Database provisioning tools for Railway MCP server.
//
// Provides:
//   - railway-create-postgres   Create a Postgres service directly (no template)
//
// Why this exists: railway-deploy-template has to read a template's
// `serializedConfig` before deploying it, and Railway refuses that read for the
// Login-with-Railway OAuth token this connector uses ("Not Authorized"). Every
// other mutation works with that token, so this tool builds the same thing the
// official Postgres template does out of primitives we already know work:
// serviceCreate (image source + variables), volumeCreate, tcpProxyCreate.
//
// The generated password is set server-side and never returned to the model.

import crypto from "node:crypto";
import { z } from "zod";
import { gql } from "graphql-request";

function toolResponse(text) {
  return { content: [{ type: "text", text }] };
}

const DATA_MOUNT = "/var/lib/postgresql/data";

export function registerDatabaseTools(server, deps) {
  const { gqlRequest, resolveEnvironmentId } = deps;

  server.tool(
    "railway-create-postgres",
    "Create a PostgreSQL database service in a Railway project without using a template: Railway's postgres-ssl image, a persistent volume, the standard PG*/DATABASE_URL variables, and a TCP proxy so DATABASE_PUBLIC_URL works (railway-query-postgres uses it). Other services can reference it as ${{<name>.DATABASE_URL}}. Use this instead of railway-deploy-template for Postgres. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe("The environment ID (defaults to the project's production environment)"),
      name: z
        .string()
        .optional()
        .describe('Service name (default "Postgres", which is what ${{Postgres.DATABASE_URL}} references expect)'),
      version: z
        .string()
        .optional()
        .describe('Postgres major version tag for ghcr.io/railwayapp-templates/postgres-ssl (default "17")'),
      publicProxy: z
        .boolean()
        .optional()
        .describe("Create a TCP proxy so the database is reachable from outside the project (default true; needed for railway-query-postgres)"),
    },
    async ({ projectId, environmentId, name, version, publicProxy }) => {
      const serviceName = name || "Postgres";
      const tag = version || "17";
      const wantProxy = publicProxy !== false;
      const steps = [];
      let serviceId;

      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const password = crypto.randomBytes(24).toString("hex");

        const variables = {
          PGDATA: `${DATA_MOUNT}/pgdata`,
          POSTGRES_USER: "postgres",
          POSTGRES_PASSWORD: password,
          POSTGRES_DB: "railway",
          PGUSER: "${{POSTGRES_USER}}",
          PGPASSWORD: "${{POSTGRES_PASSWORD}}",
          PGDATABASE: "${{POSTGRES_DB}}",
          PGHOST: "${{RAILWAY_PRIVATE_DOMAIN}}",
          PGPORT: "5432",
          DATABASE_URL:
            "postgresql://${{PGUSER}}:${{POSTGRES_PASSWORD}}@${{RAILWAY_PRIVATE_DOMAIN}}:5432/${{PGDATABASE}}",
        };
        if (wantProxy) {
          variables.DATABASE_PUBLIC_URL =
            "postgresql://${{PGUSER}}:${{POSTGRES_PASSWORD}}@${{RAILWAY_TCP_PROXY_DOMAIN}}:${{RAILWAY_TCP_PROXY_PORT}}/${{PGDATABASE}}";
        }

        // 1. Service from image, with variables set at creation so the first
        //    boot already has a password and PGDATA.
        const created = await gqlRequest(
          gql`
            mutation ($input: ServiceCreateInput!) {
              serviceCreate(input: $input) {
                id
                name
              }
            }
          `,
          {
            input: {
              projectId,
              environmentId: envId,
              name: serviceName,
              source: { image: `ghcr.io/railwayapp-templates/postgres-ssl:${tag}` },
              variables,
            },
          }
        );
        serviceId = created.serviceCreate.id;
        steps.push(`Service **${created.serviceCreate.name}** created (ID: ${serviceId})`);

        // 2. Persistent volume for the data directory.
        const vol = await gqlRequest(
          gql`
            mutation ($input: VolumeCreateInput!) {
              volumeCreate(input: $input) {
                id
                name
              }
            }
          `,
          { input: { projectId, environmentId: envId, serviceId, mountPath: DATA_MOUNT } }
        );
        steps.push(`Volume **${vol.volumeCreate.name}** mounted at \`${DATA_MOUNT}\``);

        // 3. TCP proxy so the DB is reachable from outside the project.
        if (wantProxy) {
          const proxy = await gqlRequest(
            gql`
              mutation ($input: TCPProxyCreateInput!) {
                tcpProxyCreate(input: $input) {
                  domain
                  proxyPort
                }
              }
            `,
            { input: { serviceId, environmentId: envId, applicationPort: 5432 } }
          );
          steps.push(
            `TCP proxy: ${proxy.tcpProxyCreate.domain}:${proxy.tcpProxyCreate.proxyPort} → 5432`
          );
        }

        return toolResponse(
          `Postgres created.\n\n${steps.map((s) => `- ${s}`).join("\n")}\n\n` +
            `Other services can use \`\${{${serviceName}.DATABASE_URL}}\`. ` +
            `The password was generated server-side and is stored only in the service's variables. ` +
            `First boot takes a minute or two.`
        );
      } catch (error) {
        const done = steps.length ? `\n\nCompleted before the failure:\n${steps.map((s) => `- ${s}`).join("\n")}` : "";
        const orphan = serviceId
          ? `\n\nThe service (ID: ${serviceId}) was left in place so nothing is lost; delete it in the dashboard if you want to retry from scratch.`
          : "";
        return toolResponse(`Failed to create Postgres: ${error.message}${done}${orphan}`);
      }
    }
  );
}
