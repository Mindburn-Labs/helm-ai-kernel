/**
 * HELM OpenAI-compatible JavaScript example.
 * Change ONLY the baseURL to route through HELM governance.
 */

const HELM_URL = process.env.HELM_URL || "http://localhost:8080";

async function main() {
  const response = await fetch(`${HELM_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "gpt-4",
      messages: [
        { role: "system", content: "You are a helpful assistant governed by HELM." },
        { role: "user", content: "What time is it?" },
      ],
    }),
  });

  const data = await response.json();
  console.log("Response:", data.choices?.[0]?.message?.content);
  console.log("Model:", data.model);
  console.log("ID:", data.id);
}

main().catch(console.error);
