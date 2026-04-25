import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Search } from 'lucide-react';
import { DetailList, EmptyState, ErrorState, ExternalTextLink, LoadingState, Panel, SurfaceIntro, TopStatusPill } from './components';
import { usePublicApproval, usePublicEvidence, usePublicVerification } from './hooks';
import { formatDateTime } from './model';

export function PublicTrustHomePage() {
  return (
    <div className="operator-standalone-page public">
      <SurfaceIntro
        actions={
          <Link className="operator-button primary" to="/public/verify">
            Verify a receipt
          </Link>
        }
        description="Inspect a public proof object, verify whether the published receipt is valid, and follow the evidence or approval links when they exist."
        eyebrow="Public trust"
        title="Public verification surfaces"
      />
      <div className="operator-page-grid two-up">
        <Panel
          title="Receipt verification"
          description="Check validity, timestamp, actor, and action against the public verification endpoint."
          actions={<Link className="operator-inline-link" to="/public/verify">Open lookup</Link>}
        >
          <p className="operator-panel-copy">
            Receipts are the public-facing proof anchor. Start here when you need to validate a claim.
          </p>
        </Panel>
        <Panel
          title="Evidence and approval links"
          description="Inspect the public-safe metadata exposed for supporting bundles and human approvals."
        >
          <p className="operator-panel-copy">
            These views expose only sanctioned verification details, not private operator context.
          </p>
        </Panel>
      </div>
    </div>
  );
}

export function PublicVerifyLookupPage() {
  const navigate = useNavigate();
  const [receiptId, setReceiptId] = useState('rcpt_demo');

  return (
    <div className="operator-standalone-page public">
      <SurfaceIntro
        eyebrow="Public verify"
        title="Receipt verification"
        description="Enter a receipt id to load the public verification record."
      />
      <Panel
        title="Open a receipt"
        description="This route is backed by the public verification API, not a marketing shell."
      >
        <form
          className="operator-form inline"
          onSubmit={(event) => {
            event.preventDefault();
            navigate(`/public/verify/${receiptId}`);
          }}
        >
          <label>
            <span>Receipt id</span>
            <input onChange={(event) => setReceiptId(event.target.value)} placeholder="rcpt_..." value={receiptId} />
          </label>
          <button className="operator-button primary" type="submit">
            <Search size={16} />
            Open verification
          </button>
        </form>
      </Panel>
    </div>
  );
}

export function PublicVerifyPage() {
  const { receiptId = '' } = useParams();
  const verificationQuery = usePublicVerification(receiptId);

  if (verificationQuery.isLoading) {
    return <LoadingState label="Loading public verification…" />;
  }

  if (verificationQuery.isError) {
    return (
      <div className="operator-standalone-page public">
        <ErrorState error={verificationQuery.error} title="Public verification failed" />
      </div>
    );
  }

  const receipt = verificationQuery.data?.receipt;

  return (
    <div className="operator-standalone-page public">
      <SurfaceIntro
        eyebrow="Public verify"
        title={receipt ? `Receipt ${receipt.id ?? receiptId}` : 'Receipt unavailable'}
        description="Verify whether the published receipt is authentic and inspect the public-safe fields."
      />
      {receipt ? (
        <div className="operator-page-grid two-up">
          <Panel
            title={receipt.signatureValid ? 'Verified' : 'Verification failed'}
            description="This result is derived from the public verification endpoint."
            actions={
              <TopStatusPill
                label="Signature"
                tone={receipt.signatureValid ? 'success' : 'danger'}
                value={receipt.signatureValid ? 'valid' : 'invalid'}
              />
            }
          >
            <DetailList
              items={[
                { label: 'Action', value: receipt.action ?? 'Unavailable' },
                { label: 'Actor', value: receipt.actor ?? 'Unavailable' },
                { label: 'Timestamp', value: formatDateTime(receipt.timestamp) },
                { label: 'Hash', value: receipt.hash ?? 'Unavailable' },
                { label: 'Epoch', value: String(receipt.epoch ?? 'Unavailable') },
              ]}
            />
          </Panel>
          <Panel title="Public-safe interpretation" description="What this record proves, and what it does not.">
            <ol className="operator-ordered-list">
              <li>The public endpoint attests whether the receipt signature is valid.</li>
              <li>The action and actor fields identify the published event, not private internal state.</li>
              <li>Use linked evidence or approval pages when the workflow exposes them publicly.</li>
            </ol>
          </Panel>
        </div>
      ) : (
        <EmptyState
          title="No receipt data returned"
          body="The public verifier did not return a receipt record for this id."
        />
      )}
    </div>
  );
}

export function PublicEvidencePage() {
  const { bundleId = '' } = useParams();
  const evidenceQuery = usePublicEvidence(bundleId);

  if (evidenceQuery.isLoading) {
    return <LoadingState label="Loading public evidence metadata…" />;
  }

  if (evidenceQuery.isError) {
    return (
      <div className="operator-standalone-page public">
        <ErrorState error={evidenceQuery.error} title="Evidence lookup failed" />
      </div>
    );
  }

  const evidence = evidenceQuery.data?.evidence;

  return (
    <div className="operator-standalone-page public">
      <SurfaceIntro
        eyebrow="Public evidence"
        title="Evidence bundle verification"
        description="Inspect the public-safe evidence metadata for a published bundle."
      />
      {evidence ? (
        <Panel
          title={evidenceQuery.data?.valid ? 'Evidence bundle verified' : 'Evidence bundle not verified'}
          description="PUBLIC — minimal sanctioned metadata only."
          actions={
            <TopStatusPill
              label="Status"
              tone={evidenceQuery.data?.valid ? 'success' : 'warning'}
              value={evidence.status}
            />
          }
        >
          <DetailList
            items={[
              { label: 'Bundle id', value: evidence.id },
              { label: 'Title', value: evidence.title },
              { label: 'Hash', value: evidence.hash },
              { label: 'Created', value: formatDateTime(evidence.created_at) },
            ]}
          />
        </Panel>
      ) : (
        <EmptyState title="No evidence metadata returned" body="This bundle id is not exposed publicly." />
      )}
    </div>
  );
}

export function PublicApprovalPage() {
  const { approvalId = '' } = useParams();
  const approvalQuery = usePublicApproval(approvalId);
  const detailItems = useMemo(() => {
    if (!approvalQuery.data) {
      return [];
    }

    return [
      { label: 'Approval id', value: approvalQuery.data.id },
      { label: 'Title', value: approvalQuery.data.title },
      { label: 'Status', value: approvalQuery.data.status },
      { label: 'Hash', value: approvalQuery.data.hash ?? 'Unavailable' },
      { label: 'Created', value: formatDateTime(approvalQuery.data.created_at) },
    ];
  }, [approvalQuery.data]);

  if (approvalQuery.isLoading) {
    return <LoadingState label="Loading public approval metadata…" />;
  }

  if (approvalQuery.isError) {
    return (
      <div className="operator-standalone-page public">
        <ErrorState error={approvalQuery.error} title="Approval lookup failed" />
      </div>
    );
  }

  return (
    <div className="operator-standalone-page public">
      <SurfaceIntro
        eyebrow="Public approval"
        title="Approval request"
        description="Review the public-safe approval metadata published for this request."
      />
      {approvalQuery.data ? (
        <Panel
          title={approvalQuery.data.title}
          description="Human approval metadata is published separately from private operator controls."
          actions={
            <TopStatusPill
              label="Status"
              tone={approvalQuery.data.status === 'approved' ? 'success' : 'warning'}
              value={approvalQuery.data.status}
            />
          }
        >
          <DetailList items={detailItems} />
        </Panel>
      ) : (
        <EmptyState
          title="No approval metadata returned"
          body="This approval id is not exposed publicly."
        />
      )}
      <Panel title="Need a private operator view?" description="Public routes never expose the full governed context.">
        <p className="operator-panel-copy">
          Open the internal operator shell to inspect full policy reasoning, receipts, and mutable actions.
        </p>
        <ExternalTextLink href="/workspaces" label="Go to workspaces" />
      </Panel>
    </div>
  );
}
