import { expect, test, type Page, type Route } from "@playwright/test";

const HALLMARK_WIDTHS = [320, 375, 414, 768] as const;
const smokeMode = process.env.HELM_CONSOLE_SMOKE_MODE ?? "mock";
const adminKey = process.env.HELM_CONSOLE_ADMIN_KEY ?? "dev-smoke-key";

const mockApp = {
  id: "openclaw",
  app_id: "openclaw",
  name: "OpenClaw",
  version: "v2026.5.12",
  oci_ref:
    "ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:808d750ed3ce3e29ed45d68c00c9c77ff50990204b3fe563b9f45d00f1beb88e",
  immutable_digest: "sha256:808d750ed3ce3e29ed45d68c00c9c77ff50990204b3fe563b9f45d00f1beb88e",
  oss_supported: true,
  availability: "oss_supported",
  redistribution: "allowed_by_MIT_with_upstream_notice",
  install_strategy: "signed_oci",
  required_secrets: ["model_gateway"],
  model_gateway_env: ["OPENROUTER_API_KEY"],
  declared_capabilities: ["artifact-first-launch", "receipt-backed-runtime", "mcp-firewall"],
  mcp_servers: [
    {
      id: "openclaw-mcp",
      transport: "stdio",
      risk_class: "T1",
      unknown_server_policy: "quarantine",
      unknown_tool_policy: "ESCALATE",
      schema_pin_required: true,
    },
  ],
  filesystem_needs: ["workspace:rw", "app_state:rw"],
  network_needs: ["https://openrouter.ai/api/v1"],
  healthcheck: [{ type: "command", command: "helm-launchpad-openrouter-check" }],
  teardown_recipe: {
    cascade: true,
    close_mcp_sessions: true,
    remove_container: true,
    revoke_secret_grants: true,
  },
  evidence_profile: ["launch_receipt", "mcp_quarantine", "evidence_pack"],
  risk_class: "T1",
  policy_ref: "policies/launchpad/apps/openclaw.safe.toml",
  status: {
    state: "needs_secret",
    verdict: "ESCALATE",
    reason_code: "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING",
    summary: "Required secret grant is missing; launch will not start a container.",
    missing_secrets: ["OPENROUTER_API_KEY"],
    quarantined_mcp: 1,
    offline_verifiable: false,
  },
  blocked_reason: "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING",
};

const mockSubstrate = {
  id: "local-container",
  name: "Local Container",
  kind: "local-container",
  availability: "supported",
  default_dry_run: false,
};

const mockMcpReview = {
  server_id: "openclaw-mcp",
  app_id: "openclaw",
  transport: "stdio",
  endpoint: "stdio://openclaw-tools",
  package_source: "ghcr.io/mindburn-labs/helm-launchpad/openclaw",
  publisher: "Mindburn Labs",
  digest: mockApp.immutable_digest,
  signature: "cosign://mindburn-labs/openclaw",
  tools: [
    {
      name: "read_file",
      side_effect_class: "T0",
      filesystem_needs: ["workspace:read"],
      network_needs: [],
      secret_needs: [],
      risk_class: "T0",
      approval_state: "quarantined",
    },
    {
      name: "execute_shell",
      side_effect_class: "T2",
      filesystem_needs: ["workspace:write"],
      network_needs: ["deny-by-default"],
      secret_needs: [],
      risk_class: "T2",
      approval_state: "quarantined",
    },
  ],
  unknown_tools: true,
  state: "quarantined",
  risk_class: "T1",
  policy_hash: "sha256:policy",
  proof_status: "proven",
  summary: "Unknown MCP tools remain quarantined; no side effects dispatch.",
  cli_equivalent: "helm mcp approve openclaw-mcp --tools read_file --ttl 24h --reason \"read-only demo\"",
};

async function fulfillJson(route: Route, body: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installMockBackend(page: Page) {
  await page.route("**/api/v1/**", (route) => fulfillJson(route, {}));
  await page.route("**/mcp/v1/**", (route) => fulfillJson(route, {}));
  await page.route("**/api/v1/launchpad/apps", (route) => fulfillJson(route, { apps: [mockApp], registry_apps: [mockApp] }));
  await page.route("**/api/v1/launchpad/substrates", (route) => fulfillJson(route, { substrates: [mockSubstrate] }));
  await page.route("**/api/v1/launchpad/matrix", (route) =>
    fulfillJson(route, {
      matrix: [
        {
          app_id: "openclaw",
          substrate_id: "local-container",
          launchable: false,
          verdict: "ESCALATE",
          reason: "Required secret grant is missing.",
          availability: "supported",
        },
      ],
    }),
  );
  await page.route("**/api/v1/launchpad/runs", (route) => fulfillJson(route, { runs: [] }));
  await page.route("**/api/v1/launchpad/secrets", (route) =>
    fulfillJson(route, {
      secrets: [
        {
          name: "OPENROUTER_API_KEY",
          present: false,
          scope: "runtime env",
          grant_mode: "just-in-time",
          launch_impact: "blocks launch",
        },
      ],
    }),
  );
  await page.route("**/api/v1/launchpad/mcp/threat-reviews", (route) => fulfillJson(route, { threat_reviews: [mockMcpReview] }));
  await page.route("**/api/v1/console/bootstrap", (route) =>
    fulfillJson(route, {
      version: { version: "smoke", commit: "mock", build_time: "mock", go_version: "mock" },
      workspace: { organization: "local", project: "default", environment: "smoke", mode: "mock" },
      health: { kernel: "ready", policy: "mock", store: "ready", conformance: "mock" },
      counts: { receipts: 0, pending_approvals: 0, open_incidents: 0, mcp_tools: 2 },
      receipts: [],
      conformance: { level: "L0", status: "mock" },
      mcp: { authorization: "local", scopes: ["tools:filesystem.read"] },
    }),
  );
  await page.route("**/api/v1/console/surfaces", (route) => fulfillJson(route, { surfaces: [] }));
  await page.route("**/api/v1/receipts?**", (route) => fulfillJson(route, []));
  await page.route("**/api/v1/receipts/tail?**", (route) =>
    route.fulfill({ status: 200, contentType: "text/event-stream", body: ": smoke\n\n" }),
  );
}

async function measureLayout(page: Page) {
  return await page.evaluate(() => {
    const isVisible = (el: Element) => {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
    };

    const lineCount = (el: Element) => {
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
          return node.textContent?.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
        },
      });
      const lines: number[] = [];
      while (walker.nextNode()) {
        const range = document.createRange();
        range.selectNodeContents(walker.currentNode);
        for (const rect of range.getClientRects()) {
          if (!lines.some((line) => Math.abs(line - rect.y) < 2)) lines.push(rect.y);
        }
        range.detach();
      }
      return lines.length;
    };

    const overlaps: string[] = [];
    for (const header of Array.from(document.querySelectorAll(".panel-header"))) {
      const children = Array.from(header.children).filter(isVisible);
      for (let i = 0; i < children.length; i += 1) {
        for (let j = i + 1; j < children.length; j += 1) {
          const a = children[i].getBoundingClientRect();
          const b = children[j].getBoundingClientRect();
          if (a.x < b.right - 1 && a.right > b.x + 1 && a.y < b.bottom - 1 && a.bottom > b.y + 1) {
            overlaps.push(`${children[i].textContent?.trim()} overlaps ${children[j].textContent?.trim()}`);
          }
        }
      }
    }

    const wrappedActions = Array.from(
      document.querySelectorAll("button.launchpad-action, .mobile-nav-button, .rail-link, .workbench-rail-link"),
    )
      .filter(isVisible)
      .filter((el) => lineCount(el) > 1)
      .map((el) => el.textContent?.trim().replace(/\s+/g, " "));

    return {
      horizontalScroll:
        document.documentElement.scrollWidth > window.innerWidth + 1 || document.body.scrollWidth > window.innerWidth + 1,
      overlaps,
      wrappedActions,
      verdictDrift: /\b(?:DEFER|REQUIRE_APPROVAL)\b/.test(document.body.innerText),
      rawSecretLeak: /\bsk-[A-Za-z0-9_-]{12,}\b/.test(document.body.innerText),
    };
  });
}

test.beforeEach(async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) consoleMessages.push(`${message.type()}: ${message.text()}`);
  });
  page.on("pageerror", (error) => consoleMessages.push(`pageerror: ${error.message}`));
  await page.exposeFunction("__helmConsoleMessages", () => consoleMessages);
  await page.addInitScript((key) => {
    window.sessionStorage.setItem("helm.console.admin_api_key", key);
    window.sessionStorage.setItem("helm.console.tenant_id", "default");
  }, adminKey);
  if (smokeMode === "mock") await installMockBackend(page);
});

for (const width of HALLMARK_WIDTHS) {
  test(`Launch proof workbench is stable at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 920 });
    await page.goto(`/?smoke_width=${width}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Launch / Run Timeline" })).toBeVisible();
    await expect(page.getByText("OpenClaw", { exact: true })).toBeVisible();
    await expect(page.getByText("Launch CLI: helm app run openclaw --substrate local-container")).toBeVisible();

    const layout = await measureLayout(page);
    expect(layout.horizontalScroll, "horizontal scroll").toBe(false);
    expect(layout.overlaps, "panel header overlaps").toEqual([]);
    expect(layout.wrappedActions, "wrapped primary nav/action labels").toEqual([]);
    expect(layout.verdictDrift, "legacy verdict text").toBe(false);
    expect(layout.rawSecretLeak, "raw secret leak").toBe(false);

    const messages = await page.evaluate(() => window.__helmConsoleMessages());
    expect(messages, "browser console warnings/errors").toEqual([]);
  });
}

declare global {
  interface Window {
    __helmConsoleMessages(): string[];
  }
}
