/**
 * HELM Streaming Governance Example (TypeScript)
 *
 * Demonstrates token-by-token SSE streaming through HELM's governed proxy.
 * Every streamed completion is governed: the Guardian pipeline evaluates the
 * request before forwarding, and the response is streamed to the client while
 * HELM captures the full output for receipt generation.
 *
 * Prerequisites:
 *   npm install
 *   helm proxy --upstream https://api.openai.com/v1 &
 *
 * Usage:
 *   OPENAI_API_KEY=sk-... npm start
 */
import OpenAI from 'openai';

const PROXY_URL = process.env.HELM_PROXY_URL || 'http://localhost:9090/v1';
const MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

/** Stream a chat completion through the HELM governed proxy. */
async function streamingChat(client: OpenAI, prompt: string): Promise<string> {
  const stream = await client.chat.completions.create({
    model: MODEL,
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: prompt },
    ],
    stream: true,
  });

  let fullResponse = '';
  for await (const chunk of stream) {
    const token = chunk.choices[0]?.delta?.content || '';
    process.stdout.write(token);
    fullResponse += token;
  }

  console.log(); // newline after streamed output
  return fullResponse;
}

/** Demonstrate streaming with tool definitions (governed by HELM policy). */
async function streamingWithTools(client: OpenAI): Promise<void> {
  const stream = await client.chat.completions.create({
    model: MODEL,
    messages: [
      { role: 'user', content: 'What is the weather in London?' },
    ],
    tools: [
      {
        type: 'function',
        function: {
          name: 'get_weather',
          description: 'Get current weather for a location',
          parameters: {
            type: 'object',
            properties: {
              location: { type: 'string', description: 'City name' },
            },
            required: ['location'],
          },
        },
      },
    ],
    stream: true,
  });

  let toolCallCount = 0;
  for await (const chunk of stream) {
    const delta = chunk.choices[0]?.delta;
    if (delta?.content) {
      process.stdout.write(delta.content);
    }
    if (delta?.tool_calls) {
      toolCallCount += delta.tool_calls.length;
    }
  }

  console.log();
  if (toolCallCount > 0) {
    console.log(`  Tool calls requested: ${toolCallCount}`);
  }
}

async function main(): Promise<void> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.error('Error: OPENAI_API_KEY is not set.');
    console.error('Usage: OPENAI_API_KEY=sk-... npm start');
    process.exit(1);
  }

  // Point the OpenAI client at the HELM proxy
  const client = new OpenAI({ baseURL: PROXY_URL, apiKey });

  console.log('='.repeat(60));
  console.log('HELM Streaming Governance Example (TypeScript)');
  console.log(`Proxy: ${PROXY_URL}`);
  console.log('='.repeat(60));

  // --- Example 1: Basic streaming ---
  console.log('\n--- Example 1: Basic Streaming ---\n');
  const start = performance.now();
  try {
    const response = await streamingChat(
      client,
      'Explain what an evidence pack is in 3 sentences.',
    );
    const elapsed = ((performance.now() - start) / 1000).toFixed(2);
    console.log(`\n  Characters: ${response.length}`);
    console.log(`  Time: ${elapsed}s`);
  } catch (err) {
    console.log(`\n  Denied or error: ${err instanceof Error ? err.message : err}`);
  }

  // --- Example 2: Streaming with tool calls ---
  console.log('\n--- Example 2: Streaming with Tool Calls ---\n');
  try {
    await streamingWithTools(client);
  } catch (err) {
    console.log(`\n  Denied or error: ${err instanceof Error ? err.message : err}`);
    console.log('  (This is expected if the tool is not in the HELM allowlist)');
  }

  // --- Governance artifacts ---
  console.log('\n--- Governance Artifacts ---');
  console.log();
  console.log('After streaming, HELM has generated:');
  console.log('  1. DecisionRecord  - Signed ALLOW/DENY verdict for the request');
  console.log('  2. Receipt         - Signed binding of input hash -> output hash');
  console.log('  3. ProofGraph node - Causal DAG entry linking decision to receipt');
  console.log();
  console.log('Export evidence:  helm export --evidence ./data/evidence');
  console.log('Verify receipts:  helm verify ./data/evidence');
}

main().catch(console.error);
