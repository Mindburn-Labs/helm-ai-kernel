/** Sticky toolbar for batch actions on selected proposals. */
export function BatchToolbar({
  selectedCount,
  onApprove,
  onDeny,
  onDefer,
  onClear,
}: {
  selectedCount: number;
  onApprove: () => void;
  onDeny: () => void;
  onDefer: () => void;
  onClear: () => void;
}) {
  return (
    <div
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 10,
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '10px 14px',
        borderRadius: '10px',
        background: 'rgba(109, 211, 255, 0.08)',
        border: '1px solid rgba(109, 211, 255, 0.2)',
        marginBottom: '12px',
      }}
    >
      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--operator-accent)' }}>
        {selectedCount} selected
      </span>

      <div style={{ flex: 1 }} />

      <button
        onClick={onApprove}
        style={{
          padding: '5px 12px',
          borderRadius: '6px',
          border: '1px solid rgba(121, 216, 166, 0.3)',
          background: 'rgba(121, 216, 166, 0.12)',
          color: 'var(--operator-success)',
          fontSize: '12px',
          fontWeight: 600,
          cursor: 'pointer',
        }}
        type="button"
      >
        Approve all
      </button>
      <button
        onClick={onDeny}
        style={{
          padding: '5px 12px',
          borderRadius: '6px',
          border: '1px solid rgba(255, 122, 112, 0.3)',
          background: 'rgba(255, 122, 112, 0.12)',
          color: 'var(--operator-danger)',
          fontSize: '12px',
          fontWeight: 600,
          cursor: 'pointer',
        }}
        type="button"
      >
        Deny all
      </button>
      <button
        onClick={onDefer}
        style={{
          padding: '5px 12px',
          borderRadius: '6px',
          border: '1px solid rgba(255, 185, 104, 0.3)',
          background: 'rgba(255, 185, 104, 0.12)',
          color: 'var(--operator-warning)',
          fontSize: '12px',
          fontWeight: 600,
          cursor: 'pointer',
        }}
        type="button"
      >
        Defer all
      </button>
      <button
        onClick={onClear}
        style={{
          padding: '5px 12px',
          borderRadius: '6px',
          border: '1px solid rgba(158, 178, 198, 0.2)',
          background: 'transparent',
          color: 'var(--operator-text-muted)',
          fontSize: '12px',
          fontWeight: 600,
          cursor: 'pointer',
        }}
        type="button"
      >
        Clear
      </button>
    </div>
  );
}
