import type { ReactNode } from 'react';
import { RiskLevel, TruthStage } from './domain';

export interface TruthStamp {
  stage: TruthStage;
  label: string;
  detail: string;
}

export interface StateSignal {
  key: "now" | "needs-you" | "blocked" | "risk" | "evidence" | "next";
  label: string;
  value: string;
  detail: string;
  tone: "neutral" | "info" | "success" | "warning" | "danger";
}

export interface ArtifactRef {
  id: string;
  type: "run" | "approval" | "receipt" | "evidence" | "policy" | "graph" | "goal";
  title: string;
  detail: string;
  href?: string;
  truth?: TruthStamp;
}

export interface OperatorAction {
  id: string;
  title: string;
  detail: string;
  href?: string;
  risk?: RiskLevel;
  emphasis: "primary" | "secondary" | "danger";
}

export interface ExecutionStep {
  id: string;
  title: string;
  detail: string;
  status: "pending" | "running" | "blocked" | "done" | "failed";
  dependsOn?: string[];
  artifact?: ArtifactRef;
}

export interface ExecutionPlan {
  id: string;
  title: string;
  summary: string;
  status: "draft" | "review" | "active" | "blocked" | "completed";
  steps: ExecutionStep[];
}

export interface ActivityItem {
  id: string;
  title: string;
  detail: string;
  timestamp?: string;
  tone: "neutral" | "info" | "success" | "warning" | "danger";
}

export interface InspectorTab {
  id: "overview" | "execution" | "policy" | "evidence" | "history";
  label: string;
  content: ReactNode;
}
