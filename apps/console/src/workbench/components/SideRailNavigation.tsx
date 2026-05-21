import {
  WorkbenchRail,
  WorkbenchRailLink,
  WorkbenchMobileNav,
  WorkbenchMobileNavButton,
} from "@mindburn/ui-core";
import { FLOW_NAV } from "../hooks/useWorkbenchState";
import type { FlowRoute, OperatorTask } from "../types";

interface NavigationProps {
  readonly active: FlowRoute;
  readonly tasks: readonly OperatorTask[];
  readonly onNavigate: (route: FlowRoute) => void;
}

export function Navigation({ active, tasks, onNavigate }: NavigationProps) {
  const workCount = tasks.filter(
    (task) =>
      task.route === "work" ||
      task.kind === "approval" ||
      task.kind === "connector" ||
      task.kind === "sandbox"
  ).length;

  const ledgerCount = tasks.filter((task) => task.route === "ledger").length;
  const counts: Partial<Record<FlowRoute, number>> = {
    work: workCount,
    ledger: ledgerCount,
  };

  return (
    <WorkbenchRail brand="HELM" mark="H" onBrandClick={() => onNavigate("workbench")}>
      {FLOW_NAV.map((item) => (
        <WorkbenchRailLink
          key={item.id}
          active={active === item.id}
          label={item.label}
          count={counts[item.id]}
          icon={item.icon}
          onClick={() => onNavigate(item.id)}
        />
      ))}
    </WorkbenchRail>
  );
}

interface MobileNavProps {
  readonly active: FlowRoute;
  readonly onNavigate: (route: FlowRoute) => void;
}

export function MobileNav({ active, onNavigate }: MobileNavProps) {
  return (
    <WorkbenchMobileNav>
      {FLOW_NAV.map((item) => (
        <WorkbenchMobileNavButton
          key={item.id}
          active={active === item.id}
          label={item.label}
          icon={item.icon}
          onClick={() => onNavigate(item.id)}
        />
      ))}
    </WorkbenchMobileNav>
  );
}
