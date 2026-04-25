import { Suspense } from 'react';
import { useRoutes } from 'react-router-dom';
import { ErrorBoundary } from './app/ErrorBoundary';
import { appRoutes } from './router/routes';

function SurfaceLoading() {
  return <div className="surface-loading">Loading operator surface…</div>;
}

export function App() {
  const routes = useRoutes(appRoutes);

  return (
    <ErrorBoundary>
      <Suspense fallback={<SurfaceLoading />}>{routes}</Suspense>
    </ErrorBoundary>
  );
}
