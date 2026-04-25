// @vitest-environment jsdom

import '@testing-library/jest-dom/vitest';

import { render, screen, waitFor } from '@testing-library/react';
import { RouterProvider, createMemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { appRoutes } from './routes';

vi.mock('../operator/layout', async () => {
  const reactRouterDom = await import('react-router-dom');
  return {
    OperatorLayout: () => (
      <div data-testid="operator-layout">
        operator-layout
        <reactRouterDom.Outlet />
      </div>
    ),
  };
});

vi.mock('../operator/surfaces', () => ({
  CanvasSurfacePage: () => <h1>Canvas surface</h1>,
  OperateSurfacePage: () => <h1>Operate surface</h1>,
  GovernSurfacePage: () => <h1>Govern surface</h1>,
  ProofSurfacePage: () => <h1>Proof surface</h1>,
  ChatSurfacePage: () => <h1>Chat surface</h1>,
}));

vi.mock('../operator/public', () => ({
  PublicTrustHomePage: () => <h1>Public verification surfaces</h1>,
  PublicVerifyLookupPage: () => <h1>Receipt verification</h1>,
  PublicVerifyPage: () => <h1>Receipt detail</h1>,
  PublicEvidencePage: () => <h1>Evidence bundle verification</h1>,
  PublicApprovalPage: () => <h1>Approval request</h1>,
}));

vi.mock('../operator/workspaces', () => ({
  WorkspaceListPage: () => <h1>Workspace control plane</h1>,
  WorkspaceCreatePage: () => <h1>Create a governed workspace</h1>,
  LegacyRoutePage: ({ title }: { title: string }) => <h1>{title}</h1>,
  NotFoundPage: () => <h1>Page not found</h1>,
}));

function renderRoute(initialEntry: string) {
  const router = createMemoryRouter(appRoutes, { initialEntries: [initialEntry] });

  render(<RouterProvider router={router} />);

  return router;
}

describe('app routes', () => {
  it('redirects workspace roots to the canvas surface', async () => {
    const router = renderRoute('/workspaces/workspace_acme');

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/workspaces/workspace_acme/canvas');
    });

    expect(await screen.findByRole('heading', { name: 'Canvas surface' })).toBeVisible();
  });

  it('redirects legacy welcome entry into workspace creation', async () => {
    const router = renderRoute('/welcome');

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/workspaces/new');
    });

    expect(await screen.findByRole('heading', { name: 'Create a governed workspace' })).toBeVisible();
  });

  it('renders the public receipt lookup surface directly', async () => {
    renderRoute('/public/verify');

    expect(await screen.findByRole('heading', { name: 'Receipt verification' })).toBeVisible();
  });
});
