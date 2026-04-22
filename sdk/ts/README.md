# HELM SDK — TypeScript

Typed TypeScript client for the retained HELM kernel API.

## Install

```bash
npm install @mindburn/helm
```

## Local Development

```bash
npm ci
npm test -- --run
npm run build
```

## Usage

```ts
import { HelmApiError, HelmClient } from "@mindburn/helm";

const client = new HelmClient({ baseUrl: "http://localhost:8080" });

try {
  const result = await client.chatCompletions({
    model: "gpt-4",
    messages: [{ role: "user", content: "hello" }],
  });
  console.log(result.choices[0].message.content);
} catch (error) {
  if (error instanceof HelmApiError) {
    console.log(error.reasonCode);
  }
}
```
