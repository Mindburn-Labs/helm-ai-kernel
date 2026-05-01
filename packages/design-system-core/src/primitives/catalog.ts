export type PrimitiveCategory =
  | "action"
  | "collection"
  | "disclosure"
  | "feedback"
  | "form"
  | "layout"
  | "navigation"
  | "overlay"
  | "status";

export type PrimitiveMaturity = "stable" | "product-composed" | "contract-only";

export interface PrimitiveCoverageItem {
  readonly name: string;
  readonly category: PrimitiveCategory;
  readonly exportPath: string;
  readonly maturity: PrimitiveMaturity;
  readonly comparable: readonly ("Radix" | "Ariakit" | "Geist")[];
  readonly accessibilityContract: string;
  readonly compositionContract: string;
}

export const primitiveCoverage: readonly PrimitiveCoverageItem[] = [
  coverage("Button", "action", "root", "stable", ["Geist"], "Native button semantics; icon-only usage requires an accessible label.", "Use variants for intent, not brand decoration."),
  coverage("IconButton", "action", "root", "stable", ["Radix", "Geist"], "Requires label; optional tooltip mirrors the accessible name.", "Use for compact toolbars and object actions."),
  coverage("Toolbar", "action", "root", "stable", ["Radix", "Ariakit"], "role=toolbar with explicit label.", "Compose named icon and text buttons."),
  coverage("MenuButton", "overlay", "root", "stable", ["Radix", "Ariakit"], "role=menu/menuitem with arrow-key navigation and Escape close.", "Use for short contextual action sets."),
  coverage("Popover", "overlay", "root", "stable", ["Radix", "Ariakit"], "Non-modal dialog region with outside-click and Escape close.", "Use for inspectors, filter builders, and inline detail."),
  coverage("Dialog", "overlay", "root", "stable", ["Radix", "Ariakit", "Geist"], "Focus trap, modal semantics, labelled title, optional description.", "Use for blocking confirmation and focused workflows."),
  coverage("AlertDialog", "overlay", "root", "stable", ["Radix", "Ariakit"], "role=alertdialog with explicit cancel/confirm exits.", "Use for destructive or policy-sensitive decisions."),
  coverage("Drawer", "overlay", "root", "stable", ["Radix", "Ariakit"], "Modal side panel with focus trap and close affordance.", "Use for inspectors and secondary workflows."),
  coverage("Tooltip", "overlay", "root", "stable", ["Radix", "Geist"], "role=tooltip attached by aria-describedby.", "Use only for supplementary labels, never required content."),
  coverage("Tabs", "navigation", "root", "stable", ["Radix", "Ariakit", "Geist"], "Roving tab focus with arrow keys, Home, and End.", "Use for route sections and local object views."),
  coverage("Breadcrumbs", "navigation", "root", "stable", ["Geist"], "Nav landmark with aria-current on the current page.", "Use for nested product routes."),
  coverage("Pagination", "navigation", "root", "stable", ["Geist"], "Named previous/next controls inside nav.", "Use where cursor pagination is not required."),
  coverage("Disclosure", "disclosure", "root", "stable", ["Radix", "Ariakit"], "Button controls labelled region by aria-expanded/controls.", "Use for single expandable detail."),
  coverage("Accordion", "disclosure", "root", "stable", ["Radix", "Ariakit"], "Each trigger labels a region; supports single and multiple open panels.", "Use for grouped settings, docs, and evidence detail."),
  coverage("FormField", "form", "root", "stable", ["Geist"], "Label, hint, error, invalid, required, and description wiring.", "Wrap one input control per field."),
  coverage("TextInput", "form", "root", "stable", ["Geist"], "Native input semantics with controlled and uncontrolled modes.", "Use for scalar text entry."),
  coverage("TextareaField", "form", "root", "stable", ["Geist"], "Native textarea with FormField aria wiring.", "Use for long-form governance copy."),
  coverage("SelectField", "form", "root", "stable", ["Geist"], "Native select semantics with FormField aria wiring.", "Use where native option behavior is sufficient."),
  coverage("CheckboxField", "form", "root", "stable", ["Radix", "Ariakit", "Geist"], "Native checkbox semantics with controlled and uncontrolled modes.", "Use for independent boolean settings."),
  coverage("ToggleField", "form", "root", "stable", ["Radix", "Ariakit", "Geist"], "role=switch over native checkbox semantics.", "Use for binary preferences and feature gates."),
  coverage("RadioGroup", "form", "root", "stable", ["Radix", "Ariakit", "Geist"], "Native radio group inside fieldset/legend.", "Use for mutually exclusive settings."),
  coverage("SliderField", "form", "root", "stable", ["Radix", "Ariakit", "Geist"], "Native range input with visible output.", "Use for bounded numeric settings."),
  coverage("SegmentedControl", "form", "root", "stable", ["Geist"], "radiogroup/radio semantics.", "Use for compact mode or scope selection."),
  coverage("Badge", "status", "root", "stable", ["Geist"], "Text label is primary; color and dot are secondary.", "Use for semantic state confirmation."),
  coverage("StatusPill", "status", "root", "stable", ["Geist"], "Readable state text with optional icon/dot.", "Use inside dense rows and metadata strips."),
  coverage("ProgressRail", "status", "root", "stable", ["Geist"], "Visible label/value pair; decorative fill follows semantic rail.", "Use for bounded completion."),
  coverage("ToastProvider/Toaster", "feedback", "root", "stable", ["Radix", "Geist"], "aria-live notification region with dismissible items.", "Use for transient system feedback."),
  coverage("Banner", "feedback", "root", "stable", ["Geist"], "role=status with visible title and state.", "Use for persistent route-level notices."),
  coverage("SkeletonRows", "feedback", "root", "stable", ["Geist"], "role=status loading affordance.", "Use for data loading, never as permanent placeholder."),
  coverage("Separator", "layout", "root", "stable", ["Radix", "Geist"], "Decorative by default; can expose separator semantics.", "Use to divide toolbars, panels, and menus."),
  coverage("Panel", "layout", "root", "stable", ["Geist"], "Section container with title and rail support.", "Use as the default framed primitive."),
  coverage("SplitPane", "layout", "root", "stable", ["Ariakit"], "Logical source order preserved as panes stack.", "Use for table-plus-inspector routes."),
  coverage("ActionRecordTable", "collection", "root", "product-composed", ["Geist"], "Canonical table headers and labelled record transform.", "Use for HELM-style operational records."),
  coverage("CommandPalette", "collection", "root", "product-composed", ["Ariakit", "Geist"], "Combobox/listbox dialog with active descendant.", "Use for global search and assistant entry."),
];

export const primitiveCoverageSummary = {
  stable: primitiveCoverage.filter((item) => item.maturity === "stable").length,
  productComposed: primitiveCoverage.filter((item) => item.maturity === "product-composed").length,
  total: primitiveCoverage.length,
} as const;

function coverage(
  name: string,
  category: PrimitiveCategory,
  exportPath: string,
  maturity: PrimitiveMaturity,
  comparable: readonly ("Radix" | "Ariakit" | "Geist")[],
  accessibilityContract: string,
  compositionContract: string,
): PrimitiveCoverageItem {
  return {
    name,
    category,
    exportPath,
    maturity,
    comparable,
    accessibilityContract,
    compositionContract,
  };
}
