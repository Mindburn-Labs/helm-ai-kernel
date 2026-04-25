// @vitest-environment jsdom

import '@testing-library/jest-dom/vitest';

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { ConfirmActionButton, EmptyState, SignalStrip } from './components';

describe('operator components', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('requires confirmation before dangerous actions execute', async () => {
    const onConfirm = vi.fn();

    render(
      <MemoryRouter>
        <ConfirmActionButton
          confirmLabel="Confirm deny"
          description="Denying this request will keep execution blocked."
          label="Deny"
          onConfirm={onConfirm}
        />
      </MemoryRouter>,
    );

    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    });
    expect(screen.getByText('Denying this request will keep execution blocked.')).toBeInTheDocument();
    expect(onConfirm).not.toHaveBeenCalled();

    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm deny' }));
    });
    expect(onConfirm).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'Confirm deny' })).not.toBeInTheDocument();
    });
  });

  it('auto-disarms confirmation if the operator pauses', () => {
    vi.useFakeTimers();

    render(
      <MemoryRouter>
        <ConfirmActionButton
          confirmLabel="Activate policy"
          description="Activating this policy changes future runtime verdicts."
          label="Activate"
          onConfirm={() => undefined}
          tone="warning"
        />
      </MemoryRouter>,
    );

    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Activate' }));
    });
    expect(screen.getByRole('button', { name: 'Activate policy' })).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(4_100);
    });

    expect(screen.getByRole('button', { name: 'Activate' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Activate policy' })).not.toBeInTheDocument();
  });

  it('renders the control strip with visible operator priorities', () => {
    render(
      <MemoryRouter>
        <SignalStrip
          signals={[
            { key: 'now', label: 'Now', value: '1 governed run active', detail: 'Queue is live.', tone: 'info' },
            { key: 'needs-you', label: 'Needs You', value: '1 approval pending', detail: 'Human authorization required.', tone: 'warning' },
          ]}
        />
      </MemoryRouter>,
    );

    expect(screen.getByLabelText('Operator control strip')).toBeInTheDocument();
    expect(screen.getByText('1 governed run active')).toBeVisible();
    expect(screen.getByText('1 approval pending')).toBeVisible();
  });

  it('keeps empty states explicit instead of rendering a blank shell', () => {
    render(
      <MemoryRouter>
        <EmptyState title="No imported topology" body="Import a real graph before editing policy." />
      </MemoryRouter>,
    );

    expect(screen.getByText('No imported topology')).toBeVisible();
    expect(screen.getByText('Import a real graph before editing policy.')).toBeVisible();
  });
});
