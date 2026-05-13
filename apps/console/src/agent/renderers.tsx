import { useComponent } from "@copilotkit/react-core/v2/headless";
import { z } from "zod";
import { Badge, EmptyState } from "@mindburn/ui-core";
import type { AiKernelAgentToolResult } from "./state";

const componentSchema = z.object({
  title: z.string().optional(),
  summary: z.string().optional(),
  status: z.string().optional(),
});

export function useAiKernelAgentRenderers() {
  useComponent(
    {
      name: "helm_ai_kernel_proof_result",
      description: "Render an HELM AI Kernel proof-demo tool result.",
      parameters: componentSchema,
      render: ({ title, status, summary }) => (
        <OssToolResultCard
          name={title ?? "HELM AI Kernel proof result"}
          status={status ?? "complete"}
          result={{ status: "complete", summary: summary ?? "HELM AI Kernel proof result ready." }}
        />
      ),
    },
    [],
  );
}

export function OssToolResultCard({
  name,
  status,
  parameters,
  result,
}: {
  readonly name: string;
  readonly status: string;
  readonly parameters?: Record<string, unknown>;
  readonly result?: AiKernelAgentToolResult | null;
}) {
  if (!result && status === "inProgress") {
    return <EmptyState title="Preparing tool" body={`Preparing ${name}.`} />;
  }
  return (
    <article className="agent-result-card">
      <header>
        <Badge label={result?.status ?? status} tone="proof" />
        <strong>{name.replaceAll("_", " ")}</strong>
      </header>
      <p>{result?.summary ?? `Tool ${status}`}</p>
      <dl>
        <div>
          <dt>surface</dt>
          <dd>{String(result?.data?.surface ?? parameters?.surface ?? "current")}</dd>
        </div>
        <div>
          <dt>receipts</dt>
          <dd>{String(result?.data?.receipt_count ?? "available")}</dd>
        </div>
      </dl>
    </article>
  );
}
