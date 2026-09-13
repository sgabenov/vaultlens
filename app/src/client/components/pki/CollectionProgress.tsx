import { useEffect, useState } from "react";
import { pkiJobDetails } from "../../lib/api";
import type { PkiJobDetails } from "../../../shared/pki";
export default function CollectionProgress({
  id,
  updatedAt,
}: {
  id: string;
  updatedAt: string;
}) {
  const [details, setDetails] = useState<PkiJobDetails | null>(null),
    [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void pkiJobDetails(id)
      .then((d) => {
        if (active) {
          setDetails(d);
          setError("");
        }
      })
      .catch(() => {
        if (active) {
          setDetails(null);
          setError(
            "Job details are unavailable. Refresh the session and source access.",
          );
        }
      });
    return () => {
      active = false;
    };
  }, [id, updatedAt]);
  if (error) return <p role="alert">{error}</p>;
  if (!details) return <p role="status">Loading source progress…</p>;
  return (
    <div>
      <p className="pki-muted">
        Attempt {details.job.attempt} · {details.job.concurrency} concurrent
        requests · {details.job.requestsPerSecond} requests/s
      </p>
      {details.sources.map((s) => (
        <div className="pki-box" key={s.sourceId}>
          <h3>{s.path}</h3>
          <p>
            {s.status.replace(/_/g, " ")} · {s.completed} read · {s.pending}{" "}
            pending · {s.failed} failed
          </p>
          <progress
            aria-label={`Progress for ${s.path}`}
            value={s.completed + s.failed}
            max={Math.max(s.total, 1)}
          />
          <p>Revocation evidence: {s.revocationMode.replace(/_/g, " ")}</p>
          {s.revocationError && (
            <p className="pki-muted">
              {s.revocationError}. Certificate metadata is used where available.
            </p>
          )}
          {s.error && (
            <p role="status">
              {s.errorCategory}: {s.error}
            </p>
          )}
        </div>
      ))}
      {details.errors.length > 0 && (
        <div>
          <h3>Certificate errors</h3>
          {details.errors.map((e) => (
            <p key={e.sourceId + e.serial}>
              <code>{e.serial}</code> · {e.errorCategory}: {e.error}
            </p>
          ))}
          {details.errorsTruncated && (
            <p>
              Showing the first 20 errors. Full failure counts appear above.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
