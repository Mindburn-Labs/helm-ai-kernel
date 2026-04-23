# HELM SDK — TypeScript

Typed TypeScript client for the retained HELM kernel API.

## Install

```bash
npm install @mindburn/helm
```

Published package version is `0.4.0` and is declared in `package.json`.

## Local Development

```bash
npm ci
npm test -- --run
npm run build
```

## Generated Sources

The HTTP wrapper uses OpenAPI-derived types. Protobuf bindings under `src/generated/` are generated from `protocols/proto/` with `ts-proto`.

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

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and protobuf message bindings.
