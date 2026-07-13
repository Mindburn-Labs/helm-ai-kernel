import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import * as openapiTypes from "./types.gen.js";
import * as durationProto from "./generated/google/protobuf/duration.js";
import * as timestampProto from "./generated/google/protobuf/timestamp.js";
import * as authorityProto from "./generated/helm/authority/v1/authority.js";
import * as effectsProto from "./generated/helm/effects/v1/effects.js";
import * as interventionProto from "./generated/helm/intervention/v1/intervention.js";
import * as kernelProto from "./generated/helm/kernel/v1/helm.js";
import * as truthProto from "./generated/helm/truth/v1/truth.js";

type GeneratedFunction = (...args: any[]) => any;
type MessageFns = {
  encode: GeneratedFunction;
  decode: GeneratedFunction;
  fromJSON: GeneratedFunction;
  toJSON: GeneratedFunction;
  create: GeneratedFunction;
  fromPartial: GeneratedFunction;
};

const typeSource = readFileSync(new URL("types.gen.ts", import.meta.url), "utf8");

function requiredFieldsFor(modelName: string): string[] {
  const match = typeSource.match(instanceOfPattern(modelName));
  if (!match) return [];
  return [...match[0].matchAll(/if \(!\('([^']+)' in value\)\) return false;/g)].map((field) => field[1]);
}

function instanceOfPattern(modelName: string): RegExp {
  return new RegExp(`export function instanceOf${modelName}[^]*?\\n}\\n\\nexport function ${modelName}FromJSON`);
}

function converterBodyFor(modelName: string): string {
  const match = typeSource.match(
    new RegExp(`export function ${modelName}FromJSONTyped[^]*?\\n}\\n\\nexport function ${modelName}ToJSON`),
  );
  return match?.[0] ?? "";
}

function normalizeJson(value: any): any {
  if (value == null) return value;
  if (Array.isArray(value)) return value.map(normalizeJson);
  if (typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeJson(item)]));
}

function sourceValueFor(modelName: string, field: string, expression: string, stack: string[]): any {
  const arrayMatch = expression.match(/json\['[^']+'\] as Array<any>\)\.map\(([^)]+)FromJSON\)/);
  if (arrayMatch) {
    return [sourceSampleForModel(arrayMatch[1], false, stack)];
  }
  const nestedMatch = expression.match(/([A-Za-z0-9_]+)FromJSON\(json\['[^']+'\]\)/);
  if (nestedMatch) {
    return sourceSampleForModel(nestedMatch[1], false, stack);
  }
  if (expression.includes("new Date")) return "2026-01-01T00:00:00.000Z";
  if (expression.includes("bytesFromBase64")) return "aGVsbQ==";
  if (/count|number|lamport|clock|port|limit|size|ttl|bytes|cpu|memory|score|confidence|version/i.test(field)) return 1;
  if (/enabled|allow|deny|active|valid|ok|success|required|experimental|hosted|launchable|verified/i.test(field)) return true;
  return "sample";
}

function sourceSampleForModel(modelName: string, requiredOnly = false, stack: string[] = []): any {
  if (stack.includes(modelName)) return {};
  if (modelName === "MCPJSONRPCRequestId" || modelName === "MCPJSONRPCResponseId") return 1;
  if (modelName === "MCPToolCallResponseResult") return { content: "sample" };
  if (modelName === "SandboxGrantInspection") return [];

  const body = converterBodyFor(modelName);
  const required = new Set(requiredFieldsFor(modelName));
  const sample: Record<string, unknown> = {};
  for (const match of body.matchAll(/'([^']+)': ([^\n]+),/g)) {
    const [, field, expression] = match;
    if (requiredOnly && required.size > 0 && !required.has(field)) continue;
    sample[field] = sourceValueFor(modelName, field, expression, [...stack, modelName]);
  }
  return sample;
}

function sampleForModel(modelName: string, requiredOnly = false): any {
  if (modelName === "MCPJSONRPCRequestId" || modelName === "MCPJSONRPCResponseId") {
    return 1;
  }
  if (modelName === "MCPToolCallResponseResult") {
    return { content: "sample" };
  }
  if (modelName === "SandboxGrantInspection") {
    return [];
  }
  return sourceSampleForModel(modelName, requiredOnly);
}

function modelNames(): string[] {
  return [...typeSource.matchAll(/^export function ([A-Za-z0-9_]+)FromJSON\(/gm)]
    .map((match) => match[1])
    .filter((name) => typeof (openapiTypes as any)[`${name}FromJSON`] === "function")
    .sort();
}

function expectNoThrow(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeUndefined();
  }
}

describe("generated OpenAPI TypeScript helpers", () => {
  it("preserves an explicitly null DecisionRequest context", () => {
    const request: openapiTypes.DecisionRequest = {
      action: "EXECUTE_TOOL",
      resource: "local.echo",
      context: null,
    };

    expect(openapiTypes.DecisionRequestFromJSON(request).context).toBeNull();
    expect(openapiTypes.DecisionRequestToJSON(request)).toEqual(request);
  });

  it("exercises every generated JSON converter and interface guard", () => {
    const exercised: string[] = [];

    for (const name of modelNames()) {
      const fromJSON = (openapiTypes as any)[`${name}FromJSON`] as GeneratedFunction;
      const fromJSONTyped = (openapiTypes as any)[`${name}FromJSONTyped`] as GeneratedFunction;
      const toJSON = (openapiTypes as any)[`${name}ToJSON`] as GeneratedFunction;
      const instanceOf = (openapiTypes as any)[`instanceOf${name}`] as GeneratedFunction | undefined;

      expect(fromJSON(null)).toBeNull();
      expectNoThrow(() => fromJSONTyped(null, true));
      if (toJSON) {
        expect(toJSON(null)).toBeNull();
        expect(toJSON(undefined)).toBeUndefined();
      }

      for (const requiredOnly of [false, true]) {
        const sample = sampleForModel(name, requiredOnly);
        const converted = fromJSON(sample);
        expectNoThrow(() => fromJSONTyped(sample, requiredOnly));
        if (toJSON) {
          expectNoThrow(() => toJSON(converted));
        }
      }
      if (name === "SandboxGrantInspection") {
        const grant = sampleForModel("SandboxGrant");
        const converted = fromJSON(grant);
        expectNoThrow(() => fromJSONTyped(grant, true));
        expectNoThrow(() => toJSON(converted));
      }

      if (instanceOf) {
        const required = requiredFieldsFor(name);
        const full = { ...sampleForModel(name), ...Object.fromEntries(required.map((field) => [field, "sample"])) };
        expect(instanceOf(full)).toBe(true);
        for (const field of required) {
          const missing = { ...full };
          delete missing[field];
          expect(instanceOf(missing)).toBe(false);
        }
      }
      exercised.push(name);
    }

    expect(exercised.length).toBeGreaterThan(150);
  });
});

const protoModules = [
  { exports: durationProto, source: readFileSync(new URL("generated/google/protobuf/duration.ts", import.meta.url), "utf8") },
  { exports: timestampProto, source: readFileSync(new URL("generated/google/protobuf/timestamp.ts", import.meta.url), "utf8") },
  { exports: authorityProto, source: readFileSync(new URL("generated/helm/authority/v1/authority.ts", import.meta.url), "utf8") },
  { exports: effectsProto, source: readFileSync(new URL("generated/helm/effects/v1/effects.ts", import.meta.url), "utf8") },
  { exports: interventionProto, source: readFileSync(new URL("generated/helm/intervention/v1/intervention.ts", import.meta.url), "utf8") },
  { exports: kernelProto, source: readFileSync(new URL("generated/helm/kernel/v1/helm.ts", import.meta.url), "utf8") },
  { exports: truthProto, source: readFileSync(new URL("generated/helm/truth/v1/truth.ts", import.meta.url), "utf8") },
];

function isMessageFns(value: unknown): value is MessageFns {
  return typeof value === "object"
    && value !== null
    && ["encode", "decode", "fromJSON", "toJSON", "create", "fromPartial"].every(
      (key) => typeof (value as any)[key] === "function",
    );
}

function messageBlock(source: string, messageName: string): string {
  const match = source.match(new RegExp(`export const ${messageName}: MessageFns<${messageName}> = \\{[^]*?\\n\\};`));
  return match?.[0] ?? "";
}

function nestedRepeatedFields(source: string, messageName: string): Array<[string, string]> {
  return [...messageBlock(source, messageName).matchAll(/message\.(\w+) = object\.\1\?\.map\(\(e\) => ([A-Za-z0-9_]+)\.fromPartial\(e\)\) \|\| \[\];/g)]
    .map((match) => [match[1], match[2]]);
}

function primitiveRepeatedFields(source: string, messageName: string): string[] {
  return [...messageBlock(source, messageName).matchAll(/message\.(\w+) = object\.\1\?\.map\(\(e\) => e\) \|\| \[\];/g)]
    .map((match) => match[1]);
}

function nestedOptionalFields(source: string, messageName: string): Array<[string, string]> {
  return [...messageBlock(source, messageName).matchAll(/message\.(\w+) = \(object\.\1 !== undefined && object\.\1 !== null\)\s+\? ([A-Za-z0-9_]+)\.fromPartial/g)]
    .map((match) => [match[1], match[2]]);
}

function nonDefaultValueFor(key: string, value: unknown): unknown {
  if (typeof value === "string") return `${key}-sample`;
  if (typeof value === "number") return 1;
  if (typeof value === "boolean") return true;
  if (value instanceof Uint8Array) return new Uint8Array([1, 2, 3]);
  if (Array.isArray(value)) return ["sample"];
  if (value === undefined && /(time|date|deadline|expires|issued|created|updated|completed|timestamp)/i.test(key)) {
    return new Date("2026-01-01T00:00:00.000Z");
  }
  if (value && typeof value === "object") return { key: "value" };
  return value;
}

function populatedMessage(name: string, fns: MessageFns, moduleExports: Record<string, unknown>, source: string, stack: string[] = []): any {
  const base = fns.create();
  const populated = Object.fromEntries(
    Object.entries(base).map(([key, value]) => [key, nonDefaultValueFor(key, value)]),
  );
  for (const [field, nestedName] of nestedOptionalFields(source, name)) {
    const nested = moduleExports[nestedName];
    if (isMessageFns(nested) && !stack.includes(nestedName)) {
      populated[field] = populatedMessage(nestedName, nested, moduleExports, source, [...stack, name]);
    }
  }
  for (const [field, nestedName] of nestedRepeatedFields(source, name)) {
    const nested = moduleExports[nestedName];
    if (isMessageFns(nested) && !stack.includes(nestedName)) {
      populated[field] = [populatedMessage(nestedName, nested, moduleExports, source, [...stack, name])];
    }
  }
  for (const field of primitiveRepeatedFields(source, name)) {
    populated[field] = ["sample"];
  }
  return populated;
}

function snakeCaseKeys(value: any): any {
  if (value == null || typeof value !== "object" || value instanceof Date || value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map(snakeCaseKeys);
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`),
      snakeCaseKeys(item),
    ]),
  );
}

function serviceMessageName(fn: GeneratedFunction): string | undefined {
  return String(fn).match(/([A-Za-z0-9_]+)\.encode/)?.[1];
}

describe("generated protobuf TypeScript helpers", () => {
  it("exercises message function tables and enum JSON helpers", () => {
    let messageCount = 0;
    let enumHelperCount = 0;

    for (const { exports: moduleExports, source } of protoModules) {
      for (const [name, value] of Object.entries(moduleExports)) {
        if (isMessageFns(value)) {
          const empty = value.create();
          const populated = populatedMessage(name, value, moduleExports, source);
          const emptyBytes = value.encode(empty).finish();
          const fullBytes = value.encode(populated).finish();

          expectNoThrow(() => value.decode(emptyBytes));
          expectNoThrow(() => value.decode(fullBytes));
          expectNoThrow(() => value.decode(fullBytes, fullBytes.length));
          expectNoThrow(() => value.fromJSON({}));
          expectNoThrow(() => value.fromJSON(value.toJSON(populated)));
          expectNoThrow(() => value.fromJSON(snakeCaseKeys(value.toJSON(populated))));
          expectNoThrow(() => value.toJSON(empty));
          expectNoThrow(() => value.toJSON(populated));
          expectNoThrow(() => value.fromPartial({}));
          expectNoThrow(() => value.fromPartial(populated));
          messageCount += 1;
          continue;
        }

        if (name.endsWith("FromJSON") && typeof value === "function") {
          const enumName = name.slice(0, -"FromJSON".length);
          const toJSON = (moduleExports as any)[`${enumName}ToJSON`] as GeneratedFunction | undefined;
          for (const candidate of [0, 1, -1, "UNRECOGNIZED", "not-a-real-value"]) {
            const converted = value(candidate);
            if (toJSON) {
              expect(typeof toJSON(converted)).toBe("string");
            }
          }
          enumHelperCount += 1;
        }

        if (typeof value === "object" && value !== null && !isMessageFns(value)) {
          for (const descriptor of Object.values(value as Record<string, any>)) {
            if (
              descriptor
              && typeof descriptor.requestSerialize === "function"
              && typeof descriptor.requestDeserialize === "function"
              && typeof descriptor.responseSerialize === "function"
              && typeof descriptor.responseDeserialize === "function"
            ) {
              const requestName = serviceMessageName(descriptor.requestSerialize);
              const responseName = serviceMessageName(descriptor.responseSerialize);
              const exportsByName = moduleExports as Record<string, unknown>;
              const requestFns = requestName ? exportsByName[requestName] : undefined;
              const responseFns = responseName ? exportsByName[responseName] : undefined;
              if (isMessageFns(requestFns) && isMessageFns(responseFns)) {
                const requestBytes = descriptor.requestSerialize(populatedMessage(requestName!, requestFns, moduleExports, source));
                const responseBytes = descriptor.responseSerialize(populatedMessage(responseName!, responseFns, moduleExports, source));
                expectNoThrow(() => descriptor.requestDeserialize(requestBytes));
                expectNoThrow(() => descriptor.responseDeserialize(responseBytes));
              }
            }
          }
        }
      }
    }

    expect(messageCount).toBeGreaterThan(30);
    expect(enumHelperCount).toBeGreaterThan(5);
  });
});
