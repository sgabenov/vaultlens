import { FiCheckCircle, FiAlertTriangle, FiAlertCircle, FiClock, FiSlash } from 'react-icons/fi';
import type { PkiSummary } from '../../../shared/pki';

export default function CertificateOverview({ summary, busy }: { summary: PkiSummary | null; busy: boolean }) {
  const value = (key: keyof PkiSummary) => summary ? summary[key].toLocaleString() : '—';
  const statuses = [
    { key: 'valid', label: 'Valid', hint: '', Icon: FiCheckCircle },
    { key: 'warning', label: 'Warning', hint: '≤ 30 days', Icon: FiAlertTriangle },
    { key: 'critical', label: 'Critical', hint: '≤ 7 days', Icon: FiAlertCircle },
    { key: 'expired', label: 'Expired', hint: '', Icon: FiClock },
    { key: 'revoked', label: 'Revoked', hint: '', Icon: FiSlash },
  ] as const;
  return <div className="pki-overview" aria-busy={busy}>
    <section className="pki-status-overview" aria-label="Certificate status overview">
      {statuses.map(({ key, label, hint, Icon }) => <div className={`pki-status-item pki-tone-${key}`} key={key}>
        <div className="pki-status-label"><Icon aria-hidden="true" />{label}</div>
        <strong>{value(key)}</strong>
        <span className="pki-status-hint">{hint || '\u00a0'}</span>
      </div>)}
    </section>
    <section className="pki-expiry-overview" aria-label="Upcoming expirations">
      <h2>Upcoming expirations</h2>
      <div className="pki-expiry-buckets">
        {([['critical', '≤ 7 days'], ['warning', '8–30 days'], ['near', '31–90 days'], ['later', '> 90 days']] as const).map(([key, label]) =>
          <div className={`pki-expiry-bucket pki-tone-${key}`} key={key}><strong>{value(key)}</strong><span>{label}</span></div>)}
      </div>
    </section>
    {!!summary?.revocationUnknown && <p className="pki-muted">Revocation is unknown for {summary.revocationUnknown.toLocaleString()} certificates; their status is based on expiry only.</p>}
  </div>;
}
