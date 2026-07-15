/**
 * HELM OpenAI-compatible JavaScript example.
 * Configure the governed serve runtime through environment variables.
 */

const HELM_URL = process.env.HELM_URL || "http://127.0.0.1:7714";

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required for the governed serve runtime`);
  }
  return value;
}

async function main() {
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${requiredEnv("HELM_ADMIN_API_KEY")}`,
    "X-Helm-Tenant-ID": requiredEnv("HELM_TENANT_ID"),
    "X-Helm-Principal-ID": requiredEnv("HELM_PRINCIPAL_ID"),
    "X-Helm-Session-ID": requiredEnv("HELM_SESSION_ID"),
  };
  if (process.env.HELM_WORKSPACE_ID?.trim()) {
    headers["X-Helm-Workspace-ID"] = process.env.HELM_WORKSPACE_ID.trim();
  }
  const response = await fetch(`${HELM_URL}/v1/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: "gpt-4",
      messages: [
        { role: "system", content: "You are a helpful assistant governed by HELM." },
        { role: "user", content: "What time is it?" },
      ],
    }),
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(`HELM rejected chat (${response.status}): ${JSON.stringify(data)}`);
  }
  console.log("Response:", data.choices?.[0]?.message?.content);
  console.log("Model:", data.model);
  console.log("ID:", data.id);
  console.log("Receipt:", response.headers.get("X-Helm-Receipt-ID"));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
});
