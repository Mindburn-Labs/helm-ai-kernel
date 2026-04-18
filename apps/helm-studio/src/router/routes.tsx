import { lazy } from 'react';
import { Navigate, type RouteObject } from 'react-router-dom';
import { getMergedRoutes } from '../ext';
import { OperatorLayout } from '../operator/layout';
import { PublicApprovalPage, PublicEvidencePage, PublicTrustHomePage, PublicVerifyLookupPage, PublicVerifyPage } from '../operator/public';
import { CanvasSurfacePage, ChatSurfacePage, GovernSurfacePage, OperateSurfacePage, ProofSurfacePage } from '../operator/surfaces';
import { LegacyRoutePage, NotFoundPage, WorkspaceCreatePage, WorkspaceListPage } from '../operator/workspaces';

// ─── New surface pages (lazy-loaded) ─────────────────────────────────────────

const ActionInboxPage = lazy(() =>
  import('../features/decision-inbox/pages/ActionInboxPage').then((m) => ({
    default: m.ActionInboxPage,
  })),
);

const ActionDetailPage = lazy(() =>
  import('../features/decision-inbox/pages/ActionDetailPage').then((m) => ({
    default: m.ActionDetailPage,
  })),
);

const baseRoutes: RouteObject[] = [
  {
    path: '/',
    element: <Navigate replace to="/workspaces" />,
  },
  {
    path: '/home',
    element: <Navigate replace to="/workspaces" />,
  },
  {
    path: '/welcome',
    element: <Navigate replace to="/workspaces/new" />,
  },
  {
    path: '/workspaces',
    element: <WorkspaceListPage />,
  },
  {
    path: '/workspaces/new',
    element: <WorkspaceCreatePage />,
  },
  {
    path: '/workspaces/:workspaceId',
    element: <OperatorLayout />,
    children: [
      {
        index: true,
        element: <Navigate replace to="canvas" />,
      },
      {
        path: 'canvas',
        element: <CanvasSurfacePage />,
      },
      {
        path: 'operate',
        element: <OperateSurfacePage />,
      },
      {
        path: 'govern',
        element: <GovernSurfacePage />,
      },
      {
        path: 'proof',
        element: <ProofSurfacePage />,
      },
      {
        path: 'chat',
        element: <ChatSurfacePage />,
      },
      {
        path: 'inbox',
        element: <ActionInboxPage />,
        children: [
          {
            path: ':proposalId',
            element: <ActionDetailPage />,
          },
        ],
      },
      {
        path: 'build',
        element: <Navigate replace to="../canvas" />,
      },
      {
        path: 'replay',
        element: <Navigate replace to="../proof" />,
      },
      {
        path: 'investigate',
        element: (
          <LegacyRoutePage
            description="Investigate is not a first-class operator surface in the current product because no live incident/drift workbench exists behind it."
            title="Investigate is not currently backed by live contracts"
          />
        ),
      },
      {
        path: 'integrations',
        element: (
          <LegacyRoutePage
            description="Connector catalog and health views remain secondary until they are backed by live integration contracts."
            title="Integrations are not primary in the current IA"
          />
        ),
      },
      {
        path: '*',
        element: <NotFoundPage />,
      },
    ],
  },
  {
    path: '/public',
    element: <PublicTrustHomePage />,
  },
  {
    path: '/public/verify',
    element: <PublicVerifyLookupPage />,
  },
  {
    path: '/public/verify/:receiptId',
    element: <PublicVerifyPage />,
  },
  {
    path: '/public/evidence/:bundleId',
    element: <PublicEvidencePage />,
  },
  {
    path: '/public/approval/:approvalId',
    element: <PublicApprovalPage />,
  },
  {
    path: '*',
    element: <NotFoundPage />,
  },
];

export const appRoutes = getMergedRoutes(baseRoutes) as RouteObject[];
