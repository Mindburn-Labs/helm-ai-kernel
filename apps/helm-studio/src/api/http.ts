import { apiPath } from "./baseUrl";

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, message: string, detail: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function parseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

export async function requestJson<T>(
  input: Parameters<typeof fetch>[0],
  init?: Parameters<typeof fetch>[1],
): Promise<T> {
  // Rewrite absolute paths through the configured base URL (see baseUrl.ts).
  // Non-string inputs (Request, URL) pass through unchanged so callers that
  // already built a fully-qualified URL control their own target.
  const resolved = typeof input === "string" ? apiPath(input) : input;
  const response = await fetch(resolved, {
    credentials: "include",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  const body = await parseBody(response);
  if (!response.ok) {
    const message =
      typeof body === "object" && body && "error" in body
        ? String((body as { error: unknown }).error)
        : response.statusText || "Request failed";
    throw new ApiError(response.status, message, body);
  }

  return body as T;
}

export function asJsonBody(body: unknown): Parameters<typeof fetch>[1] {
  return {
    method: "POST",
    body: JSON.stringify(body),
  };
}
