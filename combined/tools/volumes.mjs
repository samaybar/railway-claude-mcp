// Volume management tools for Railway MCP server.
// Registered against an existing McpServer instance.
//
// Provides:
//   - railway-create-volume   Create and attach a volume to a service at a mount path
//   - railway-list-volumes    List all volumes in a project with their attachments
//   - railway-delete-volume   Permanently delete a volume by ID
//
// Uses the same gqlRequest + resolveEnvironmentId helpers as the main server,
// passed in via the deps argument so we don't duplicate the GraphQL client.

import { z } from "zod";
import { gql } from "graphql-request";

function toolResponse(text) {
  return { content: [{ type: "text", text }] };
}

export function registerVolumeTools(server, deps) {
  const { gqlRequest, resolveEnvironmentId } = deps;

  // -- railway-create-volume --
  server.tool(
    "railway-create-volume",
    "Create a new volume and attach it to a service at the given mount path. The service will be redeployed automatically by Railway. environmentId defaults to the project's production environment.",
    {
      projectId: z.string().describe("The project ID"),
      environmentId: z
        .string()
        .optional()
        .describe(
          "The environment ID (defaults to the project's production environment)"
        ),
      serviceId: z.string().describe("The service ID to attach the volume to"),
      mountPath: z
        .string()
        .describe(
          "Absolute path inside the container where the volume should be mounted (e.g., /data)"
        ),
    },
    async ({ projectId, environmentId, serviceId, mountPath }) => {
      try {
        const envId = await resolveEnvironmentId(projectId, environmentId);
        const data = await gqlRequest(
          gql`
            mutation ($input: VolumeCreateInput!) {
              volumeCreate(input: $input) {
                id
                name
                volumeInstances {
                  edges {
                    node {
                      id
                      mountPath
                      environmentId
                      serviceId
                    }
                  }
                }
              }
            }
          `,
          {
            input: {
              projectId,
              environmentId: envId,
              serviceId,
              mountPath,
            },
          }
        );

        const v = data.volumeCreate;
        const inst = v.volumeInstances?.edges?.[0]?.node;
        return toolResponse(
          `Volume created: **${v.name}** (ID: ${v.id})\n\n` +
            `Mounted at: \`${inst?.mountPath || mountPath}\`\n` +
            `Service: ${inst?.serviceId || serviceId}\n` +
            `Environment: ${inst?.environmentId || envId}\n\n` +
            `Railway will redeploy the service automatically.`
        );
      } catch (error) {
        return toolResponse(`Failed to create volume: ${error.message}`);
      }
    }
  );

  // -- railway-list-volumes --
  server.tool(
    "railway-list-volumes",
    "List all volumes in a project, including which services they are attached to and their mount paths.",
    {
      projectId: z.string().describe("The project ID"),
    },
    async ({ projectId }) => {
      try {
        const data = await gqlRequest(
          gql`
            query ($id: String!) {
              project(id: $id) {
                volumes {
                  edges {
                    node {
                      id
                      name
                      createdAt
                      volumeInstances {
                        edges {
                          node {
                            id
                            mountPath
                            sizeMB
                            currentSizeMB
                            state
                            serviceId
                            environmentId
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

        const volumes = data.project?.volumes?.edges?.map((e) => e.node) || [];
        if (volumes.length === 0) {
          return toolResponse("No volumes found in this project.");
        }

        const formatted = volumes
          .map((v) => {
            const insts = v.volumeInstances?.edges?.map((e) => e.node) || [];
            const instLines = insts.length
              ? insts
                  .map(
                    (i) =>
                      `  - mount: \`${i.mountPath}\` | service: ${i.serviceId} | env: ${i.environmentId} | size: ${i.currentSizeMB ?? 0}/${i.sizeMB ?? "?"} MB | state: ${i.state}`
                  )
                  .join("\n")
              : "  (no instances)";
            return `**${v.name}** (ID: ${v.id})\n${instLines}`;
          })
          .join("\n\n");

        return toolResponse(
          `Found ${volumes.length} volume(s):\n\n${formatted}`
        );
      } catch (error) {
        return toolResponse(`Failed to list volumes: ${error.message}`);
      }
    }
  );

  // -- railway-delete-volume --
  server.tool(
    "railway-delete-volume",
    "Delete a volume by ID. This permanently destroys the volume and its data — use with care.",
    {
      volumeId: z.string().describe("The volume ID to delete"),
    },
    async ({ volumeId }) => {
      try {
        await gqlRequest(
          gql`
            mutation ($volumeId: String!) {
              volumeDelete(volumeId: $volumeId)
            }
          `,
          { volumeId }
        );
        return toolResponse(`Volume ${volumeId} deleted.`);
      } catch (error) {
        return toolResponse(`Failed to delete volume: ${error.message}`);
      }
    }
  );
}
