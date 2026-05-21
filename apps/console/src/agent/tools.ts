import { useFrontendTool } from "@copilotkit/react-core/v2";
import { z } from "zod";

const surfaceSchema = z.object({ surface: z.string().min(1) });
const receiptSchema = z.object({ receipt_id: z.string().min(1) });
const querySchema = z.object({ query: z.string() });
const demoSchema = z.object({ action: z.string().min(1) });

export interface AiKernelFrontendToolHandlers {
  readonly navigateSurface: (surface: string) => void;
  readonly selectReceipt: (receiptId: string) => void;
  readonly setSearchQuery: (query: string) => void;
  readonly chooseDemoAction: (action: string) => void;
}

export function useAiKernelFrontendTools(handlers: AiKernelFrontendToolHandlers) {
  useFrontendTool(
    {
      name: "navigate_surface",
      description: "Read-only navigation. HELM AI cannot approve, launch, inject secrets, or delete evidence.",
      parameters: surfaceSchema,
      handler: async ({ surface }) => {
        handlers.navigateSurface(surface);
        return { status: "complete", surface };
      },
    },
    [handlers],
  );

  useFrontendTool(
    {
      name: "select_receipt",
      description: "Read-only receipt selection for explanation or summarization.",
      parameters: receiptSchema,
      handler: async ({ receipt_id }) => {
        handlers.selectReceipt(receipt_id);
        return { status: "complete", receipt_id };
      },
    },
    [handlers],
  );

  useFrontendTool(
    {
      name: "set_search_query",
      description: "Read-only search query update. No side effect is authorized.",
      parameters: querySchema,
      handler: async ({ query }) => {
        handlers.setSearchQuery(query);
        return { status: "complete", query };
      },
    },
    [handlers],
  );

  useFrontendTool(
    {
      name: "choose_demo_action",
      description: "Choose a proof demo action without executing it or authorizing side effects.",
      parameters: demoSchema,
      handler: async ({ action }) => {
        handlers.chooseDemoAction(action);
        return { status: "complete", action };
      },
    },
    [handlers],
  );
}
