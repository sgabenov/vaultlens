import { pkiEngineUrl } from "../../shared/pkiEngine";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AxiosError } from "axios";
import * as api from "../lib/api";
import type {
  CertificateRecord,
  PkiCondition,
  PkiJob,
  PkiQuery,
  PkiSource,
  PkiSummary,
} from "../../shared/pki";
import { restorePkiQuery, pkiSelectionKey } from "../../shared/pkiSelection";
import CertificateOverview from "../components/pki/CertificateOverview";
import CollectionProgress from "../components/pki/CollectionProgress";
import CertificateSearch from "../components/pki/CertificateSearch";
import CertificateDialog from "../components/pki/CertificateDialog";
import CertificatePagination from "../components/pki/CertificatePagination";
import CertificateBatchControls from "../components/pki/CertificateBatchControls";
import { pkiBatchLimit, type PkiBatchRef } from "../../shared/pkiBatch";
import DropdownChevron from "../components/common/DropdownChevron";
import "../components/pki/pki.css";
const coverageText: Record<string, string> = {
  complete: "All listed certificates read; revocation evidence available.",
  partial:
    "Some listing or certificate reads failed. The catalog is incomplete.",
  revocation_unknown:
    "Listed certificates read; some revocation evidence is unavailable.",
  not_collected: "No completed observation yet.",
};
const emptyCondition: PkiCondition = {
  field: "cn",
  operator: "contains",
  value: "",
};
const labelType: Record<string, string> = {
  server: "Server",
  client: "Client",
  both: "Server + client",
  ca: "CA",
  unknown: "Other / unknown",
};
const labelRevocation: Record<string, string> = {
  revoked: "Revoked",
  not_revoked: "Not revoked",
  unknown: "Unknown",
};
const labelUsage: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "Server authentication",
  "1.3.6.1.5.5.7.3.2": "Client authentication",
  "1.3.6.1.5.5.7.3.3": "Code signing",
  "1.3.6.1.5.5.7.3.4": "Email protection",
};
const message = (e: unknown) =>
  e instanceof AxiosError
    ? e.response?.data?.error || e.message
    : e instanceof Error
      ? e.message
      : "Request failed";
const date = (n: number) => new Date(n).toISOString().slice(0, 10);
function validity(c: CertificateRecord) {
  const now = Date.now();
  return c.notAfter <= now
    ? "Expired"
    : c.notBefore > now
      ? "Not yet valid"
      : c.notAfter - now <= 30 * 86400000
        ? "Expiring"
        : "Valid";
}
export default function CertificatesPage() {
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState("inventory"),
    [sources, setSources] = useState<PkiSource[]>([]),
    [selected, setSelected] = useState<string[]>([]);
  const [conditions, setConditions] = useState<PkiCondition[]>([
      { ...emptyCondition },
    ]),
    [match, setMatch] = useState<"all" | "any">("all");
  const [type, setType] = useState(""),
    [valid, setValid] = useState(""),
    [revoked, setRevoked] = useState(""),
    [sort, setSort] = useState<"cn" | "notAfter">("notAfter");
  const [summary, setSummary] = useState<PkiSummary | null>(null);
  const [rows, setRows] = useState<CertificateRecord[]>([]),
    [total, setTotal] = useState(0),
    [page, setPage] = useState(1),
    [pageSize, setPageSize] = useState(50);
  const [query, setQuery] = useState<PkiQuery | null>(null),
    [jobs, setJobs] = useState<PkiJob[]>([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [ready, setReady] = useState(false);
  const [detail, setDetail] = useState<Awaited<
    ReturnType<typeof api.pkiCertificate>
  > | null>(null);
  const generation = useRef(0),
    detailGeneration = useRef(0);
  const [expandedJob, setExpandedJob] = useState<string | null>(null),
    [actionBusy, setActionBusy] = useState(false);
  const [checkedCertificates, setCheckedCertificates] = useState<Map<number, PkiBatchRef>>(new Map());
  const selectionScope = query ? JSON.stringify({ sources: query.sources, conditions: query.conditions, match: query.match, type: query.type, validity: query.validity, revocation: query.revocation, sort: query.sort, direction: query.direction }) : "";
  useEffect(() => { setCheckedCertificates(new Map()); }, [selectionScope]);
  function selectCertificates(certificates: CertificateRecord[], checked: boolean) {
    const next = new Map(checkedCertificates);
    for (const c of certificates) {
      if (checked) next.set(c.id, { id: c.id, sourceId: c.sourceId, fingerprint: c.fingerprint, serial: c.serial, cn: c.cn, sourcePath: c.sourcePath });
      else next.delete(c.id);
    }
    if (next.size > pkiBatchLimit) { setError("Select up to 10,000 certificates; narrow the search first"); return; }
    setCheckedCertificates(next);
  }
  const checkedOnPage = rows.filter(c => checkedCertificates.has(c.id)).length;
  const filterParams = params.toString();
  const canSaveSelection = useRef(false);
  const sourcePicker = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    function dismissSourcePicker(event: PointerEvent | FocusEvent) {
      const picker = sourcePicker.current;
      if (picker?.open && event.target instanceof Node && !picker.contains(event.target)) {
        picker.open = false;
      }
    }
    document.addEventListener("pointerdown", dismissSourcePicker, true);
    document.addEventListener("focusin", dismissSourcePicker);
    return () => {
      document.removeEventListener("pointerdown", dismissSourcePicker, true);
      document.removeEventListener("focusin", dismissSourcePicker);
    };
  }, []);
  async function run(q: PkiQuery) {
    const gen = ++generation.current;
    setBusy(true);
    setSummary(null);
    setError("");
    setDetail(null);
    detailGeneration.current++;
    try {
      const [r, scope] = await Promise.all([api.pkiQuery(q), api.pkiSources()]);
      if (gen !== generation.current) return;
      setSources(scope.sources);
      setSelected((ids) =>
        ids.filter((id) => scope.sources.some((s) => s.id === id)),
      );
      if (q.sources.some((id) => !scope.sources.some((s) => s.id === id)))
        throw new Error("Source access changed. Apply the current selection.");
      if ((q.offset ?? 0) > 0 && (q.offset ?? 0) >= r.total) {
        void run({ ...q, offset: Math.max(0, Math.ceil(r.total / q.limit) - 1) * q.limit });
        return;
      }
      setSummary(r.summary);
      setRows(r.certificates);
      setTotal(r.total);
      setPage(Math.floor((q.offset ?? 0) / q.limit) + 1);
      setPageSize(q.limit);
      setQuery(q);
    } catch (e) {
      if (gen === generation.current) {
        setError(message(e));
        setQuery(null);
        setSummary(null);
      setRows([]);
        setTotal(0);

      }
    } finally {
      if (gen === generation.current) setBusy(false);
    }
  }
  useEffect(() => {
    let cancelled = false;
    canSaveSelection.current = false;
    setPage(1);
    setReady(false);
    setRows([]);
    setQuery(null);
    setDetail(null);

    setTotal(0);
    void api
      .pkiSources()
      .then((r) => {
        if (cancelled) return;
        setSources(r.sources);
        let saved: unknown;
        try {
          saved = JSON.parse(sessionStorage.getItem(pkiSelectionKey) || "null");
        } catch {
          /* Browser storage may be unavailable. */
        }
        const q = restorePkiQuery(
          new URLSearchParams(filterParams),
          r.sources,
          saved,
        );
        canSaveSelection.current = true;
        setSelected(q.sources);
        setReady(true);
        setConditions(
          q.conditions.length ? q.conditions : [{ ...emptyCondition }],
        );
        setMatch(q.match);
        setType(q.type ?? "");
        setValid(q.validity ?? "");
        setRevoked(q.revocation ?? "");
        setSort(q.sort);
        void run(q);
      })
      .catch((e) => {
        if (!cancelled) {
          setError(message(e));
          setReady(true);
        }
      });
    return () => {
      cancelled = true;
      generation.current++;
      detailGeneration.current++;
    };
  }, [filterParams]);
  useEffect(() => {
    if (ready && canSaveSelection.current) {
      try {
        sessionStorage.setItem(pkiSelectionKey, JSON.stringify(selected));
      } catch {
        /* Selection still works without storage. */
      }
    }
  }, [selected, ready]);
  function acceptSources(nextSources: PkiSource[]) {
    setSources(nextSources);
    setSelected((ids) =>
      ids.filter((id) => nextSources.some((s) => s.id === id)),
    );
    if (query?.sources.some((id) => !nextSources.some((s) => s.id === id))) {
      generation.current++;
      detailGeneration.current++;
      setSummary(null);
      setRows([]);
      setQuery(null);
      setDetail(null);

      setTotal(0);
      setBusy(false);
      setError(
        "Source access changed. Apply the current authorized selection.",
      );
    }
  }
  useEffect(() => {
    if (tab !== "jobs") return;
    let active = true,
      loading = false;
    const load = () => {
      if (document.visibilityState === "hidden" || loading) return;
      loading = true;
      void api
        .pkiJobs()
        .then((r) => {
          if (active) {
            setJobs(r.jobs);
            void api
              .pkiSources()
              .then((s) => {
                if (active) acceptSources(s.sources);
              })
              .catch(() => {});
          }
        })
        .catch((e) => {
          if (active) {
            setError(message(e));
            setJobs([]);
            setExpandedJob(null);
          }
        })
        .finally(() => {
          loading = false;
        });
    };
    load();
    const timer = setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [tab]);
  function search() {
    const q: PkiQuery = {
      sources: selected,
      conditions: conditions.filter((c) => c.value.trim()),
      match,
      type,
      validity: valid,
      revocation: revoked,
      sort,
      direction: "asc",
      limit: pageSize,
    };
    setPage(1);
    const encoded = new URLSearchParams({
      filter: JSON.stringify(q),
    }).toString();
    if (encoded === filterParams) void run(q);
    else setParams({ filter: JSON.stringify(q) });
  }
  async function collect() {
    setBusy(true);
    setError("");
    try {
      await api.pkiCollect(selected);
      setTab("jobs");
      setJobs((await api.pkiJobs()).jobs);
    } catch (e) {
      setError(message(e));
      if (e instanceof AxiosError && e.response?.status === 409) setTab("jobs");
    } finally {
      setBusy(false);
    }
  }
  async function open(c: CertificateRecord) {
    const gen = ++detailGeneration.current;
    setError("");
    try {
      const d = await api.pkiCertificate(c.id);
      if (gen === detailGeneration.current) setDetail(d);
    } catch (e) {
      if (gen === detailGeneration.current) setError(message(e));
    }
  }
  async function jobAction(id: string, action: "pause" | "resume") {
    setActionBusy(true);
    try {
      await api.pkiJobAction(id, action);
      setJobs((await api.pkiJobs()).jobs);
    } catch (e) {
      setError(message(e));
    } finally {
      setActionBusy(false);
    }
  }
  function downloadPem() {
    if (!detail) return;
    const url = URL.createObjectURL(
      new Blob([detail.pem], { type: "application/x-pem-file" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `${detail.certificate.serial}.pem`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function exportRecords() {
    if (!query) return;
    const a = document.createElement("a");
    a.href =
      "/api/pki/export?filter=" +
      encodeURIComponent(JSON.stringify({ ...query, cursor: undefined }));
    a.download = "certificates.ndjson";
    a.click();
  }
  useEffect(() => {
    if (!ready || tab === "jobs") return;
    void api
      .pkiSources()
      .then((r) => acceptSources(r.sources))
      .catch((e) => setError(message(e)));
  }, [tab, ready]);
  return (
    <div className="pki-workspace">
      <div className="pki-row pki-spread">
        <div>
          <h1>Certificates</h1>
          <p className="pki-muted">
            PKI inventory · collected public certificates
          </p>
        </div>
        <button
          disabled={busy || !selected.length}
          onClick={() => void collect()}
        >
          Collect selected sources
        </button>
      </div>
      <nav className="pki-tabs" aria-label="Certificate workspace">
        {[
          ["inventory", "Inventory"],
          ["sources", "Sources"],
          ["jobs", "Collection jobs"],
        ].map(([id, label]) => (
          <button
            key={id}
            aria-current={tab === id ? "page" : undefined}
            className={tab === id ? "selected" : ""}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>
      {error && (
        <div className="pki-error" role="alert">
          {error}
        </div>
      )}
      {tab === "inventory" && (
        <>
          <CertificateOverview summary={query ? summary : null} busy={busy} />
          <div className="pki-row pki-spread">
            <span className="pki-muted">
              {query?.sources.length ?? selected.length} sources in result scope
              ·{" "}
              {
                sources.filter(
                  (s) =>
                    (query?.sources ?? selected).includes(s.id) &&
                    s.coverage === "complete",
                ).length
              }{" "}
              completely collected at last observation
            </span>
            <button
              disabled={busy || !query}
              onClick={() => query && void run(query)}
            >
              Refresh results
            </button>
          </div>
          <CertificateSearch
            scope={<div className="pki-search-scope">
              <div className="pki-source-field">
                <span>Sources</span>
                <details className="pki-source-picker" ref={sourcePicker} onKeyDown={(event) => {
                  if (event.key === "Escape" && event.currentTarget.open) {
                    event.preventDefault();
                    event.currentTarget.open = false;
                    event.currentTarget.querySelector("summary")?.focus();
                  }
                }}>
                  <summary className="ui-dropdown-control">
                    <span>{selected.length === sources.length ? `All ${sources.length} sources` : `${selected.length} sources selected`}</span>
                    <DropdownChevron />
                  </summary>
                  <div className="pki-source-options">
                    <label><input type="checkbox" checked={!!sources.length && selected.length === sources.length} onChange={(e) => setSelected(e.target.checked ? sources.map(s => s.id) : [])} />All authorized sources</label>
                    {sources.map(source => <label key={source.id}><input type="checkbox" checked={selected.includes(source.id)} onChange={(e) => setSelected(e.target.checked ? [...selected, source.id] : selected.filter(id => id !== source.id))} />{source.path}{source.namespace ? ` · ${source.namespace}` : ""}</label>)}
                    {!sources.length && <span>No authorized sources</span>}
                  </div>
                </details>
              </div>
            <label>
              Usage type{" "}
              <select value={type} onChange={(e) => setType(e.target.value)}>
                <option value="">All types</option>
                {Object.entries(labelType).map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Validity{" "}
              <select value={valid} onChange={(e) => setValid(e.target.value)}>
                <option value="">Any</option>
                <option value="valid">Currently valid</option>
                <option value="expiring">Expires within 30 days</option>
                <option value="expired">Expired</option>
                <option value="not_yet_valid">Not yet valid</option>
              </select>
            </label>
            <label>
              Revocation{" "}
              <select
                value={revoked}
                onChange={(e) => setRevoked(e.target.value)}
              >
                <option value="">Any</option>
                {Object.entries(labelRevocation).map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </label>

            </div>}
            resultLabel={busy ? "Loading…" : `${query?.sources.length ?? selected.length} sources · ${total.toLocaleString()} results`}
            onReset={() => {
              setSelected(sources.map(s => s.id));
              setType(""); setValid(""); setRevoked("");
              setMatch("all"); setConditions([{ ...emptyCondition }]);
            }}
            conditions={conditions}
            onChange={setConditions}
            match={match}
            onMatch={setMatch}
            onSearch={search}
            disabled={busy || !ready}
          />
          {detail && (
            <CertificateDialog onClose={() => {
                    setDetail(null);
                    detailGeneration.current++;
                  }}>
              <div className="pki-certificate-summary">
                <aside>
                  <span className={`pki-badge ${detail.certificate.notAfter <= Date.now() ? "expired" : ""}`}>{validity(detail.certificate)}</span>
                  <dl>
                    <dt>Valid from</dt><dd>{new Date(detail.certificate.notBefore).toISOString().replace("T", " ").replace(".000Z", " UTC")}</dd>
                    <dt>Expires at</dt><dd>{new Date(detail.certificate.notAfter).toISOString().replace("T", " ").replace(".000Z", " UTC")}</dd>
                    <dt>Revocation</dt><dd>{labelRevocation[detail.certificate.revoked]}</dd>
                  </dl>
                </aside>
                <div>
                  <h3>{detail.certificate.cn || detail.certificate.serial}</h3>
                  <dl className="pki-certificate-facts">
                    <div><dt>Source</dt><dd>{detail.certificate.sourcePath || detail.certificate.sourceId}</dd></div>
                    <div><dt>Certificate type</dt><dd>{labelType[detail.certificate.type]}</dd></div>
                    <div><dt>Issuer</dt><dd>{detail.certificate.issuer}</dd></div>
                    <div><dt>Usage</dt><dd>{detail.certificate.eku.map(oid => labelUsage[oid] || oid).join(", ") || "Not specified"}</dd></div>
                    <div><dt>SAN</dt><dd>{detail.certificate.sans.map(s => `${s.type}: ${s.value}`).join("\n") || "None"}</dd></div>
                  </dl>
                </div>
              </div>
              <details className="pki-certificate-technical">
                <summary>Technical details</summary>
              <dl className="pki-detail-grid">
                {[
                  ["Serial", detail.certificate.serial],
                  ["SHA-256", detail.certificate.fingerprint],
                  ["Subject", detail.certificate.subject],
                  ["Issuer", detail.certificate.issuer],
                  ["Issuer evidence", detail.issuerState],
                  ["Role attribution", "Unknown — no issuance evidence"],
                  [
                    "Public key",
                    `${detail.certificate.algorithm} ${detail.certificate.curve || detail.certificate.keySize}`,
                  ],
                  [
                    "Validity",
                    `${date(detail.certificate.notBefore)} → ${date(detail.certificate.notAfter)}`,
                  ],
                  ["Source presence", detail.certificate.presence],
                  ["Last observed", detail.certificate.lastSeen],
                  [
                    "Revocation observed",
                    detail.certificate.revocationObservedAt || "Unknown",
                  ],
                  ["Revocation", labelRevocation[detail.certificate.revoked]],
                  [
                    "SAN",
                    detail.certificate.sans
                      .map((s) => `${s.type}: ${s.value}`)
                      .join("\n") || "None",
                  ],
                ].map(([k, v]) => (
                  <div key={k}>
                    <dt>{k}</dt>
                    <dd>{v}</dd>
                  </div>
                ))}
              </dl>
              </details>
              <p className="pki-muted">
                Signing CA verification checks this certificate signature, not
                the complete trust chain. Validity is calculated now; revocation
                reflects the last observation.
              </p>
              {!!detail.conflicts?.observations.length && (
                <div role="status" className="pki-error">
                  <strong>Certificate identity conflict</strong>
                  <p>
                    The original certificate is retained. Vault returned
                    different content for this source and serial.
                  </p>
                  {detail.conflicts.observations.map((c) => (
                    <p key={c.observedFingerprint}>
                      <code>{c.observedFingerprint}</code>
                      <br />
                      {c.observations} observations · {c.firstSeen} to{" "}
                      {c.lastSeen}
                    </p>
                  ))}
                  {detail.conflicts.truncated && (
                    <p>Only the first 20 conflicts are shown.</p>
                  )}
                </div>
              )}
              <div className="pki-row">
                <button onClick={downloadPem}>Download PEM</button>
                <Link
                  to={pkiEngineUrl(detail.certificate.sourcePath!, {
                    source: detail.certificate.sourceId,
                    certificate: detail.certificate.serial,
                    record: detail.certificate.id,
                  })}
                >
                  Open certificate in PKI engine
                </Link>
              </div>
              <details>
                <summary>Public certificate</summary>
                <pre>{detail.pem}</pre>
              </details>
              {detail.issuer && (
                <details>
                  <summary>Verified signing CA</summary>
                  <pre>{detail.issuer.pem}</pre>
                </details>
              )}
            </CertificateDialog>
          )}
          <div className="pki-row pki-spread pki-controls">
            <span aria-live="polite">
              {busy
                ? "Loading…"
                : `${total.toLocaleString()} matching certificates`}
            </span>
            <div className="pki-row">
              <label>
                Sort{" "}
                <select
                  value={sort}
                  onChange={(e) => setSort(e.target.value as "cn" | "notAfter")}
                >
                  <option value="notAfter">Expiry date</option>
                  <option value="cn">Common name</option>
                </select>
              </label>
              <button
                disabled={!query || busy}
                onClick={() => void exportRecords()}
              >
                Export NDJSON
              </button>
            </div>
          </div>
          <p className="pki-muted">
            Export uses the applied search and a consistent snapshot. A complete
            download ends with a completion record; interrupted exports are
            incomplete. Maximum download duration: two minutes.
          </p>
          <div className="pki-box pki-table">
            <table>
              <thead>
                <tr>
                  <th className="pki-selection-cell"><input type="checkbox" aria-label="Select certificates on this page" disabled={busy || !rows.length}
                    checked={!!rows.length && checkedOnPage === rows.length}
                    ref={node => { if (node) node.indeterminate = checkedOnPage > 0 && checkedOnPage < rows.length; }}
                    onChange={e => selectCertificates(rows, e.target.checked)} /></th>
                  <th>Common name / serial</th>
                  <th>Source / type</th>
                  <th>Validity</th>
                  <th>Revocation</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.id} className={checkedCertificates.has(c.id) ? "pki-selected-row" : undefined}>
                    <td className="pki-selection-cell"><input type="checkbox" aria-label={`Select ${c.cn || c.serial}`} checked={checkedCertificates.has(c.id)} disabled={busy} onChange={e => selectCertificates([c], e.target.checked)} /></td>
                    <td>
                      <button className="pki-link" onClick={() => void open(c)}>
                        {c.cn || "(no common name)"}
                      </button>
                      <small>{c.serial}</small>
                    </td>
                    <td>
                      <Link
                        to={pkiEngineUrl(c.sourcePath!, {
                          source: c.sourceId,
                          certificate: c.serial,
                          record: c.id,
                        })}
                      >
                        {c.sourcePath} · View in engine
                      </Link>
                      <small>{labelType[c.type]}</small>
                    </td>
                    <td>
                      <span
                        className={`pki-badge ${c.notAfter < Date.now() ? "expired" : ""}`}
                      >
                        {validity(c)}
                      </span>
                      <small>{date(c.notAfter)}</small>
                    </td>
                    <td>
                      {labelRevocation[c.revoked]}
                      {c.presence === "not_observed" && (
                        <small>
                          Not observed in latest complete collection
                        </small>
                      )}
                    </td>
                    <td><button type="button" onClick={() => void open(c)} aria-label={`Details for ${c.cn || c.serial}`}>Details</button></td>
                  </tr>
                ))}
                {!rows.length && (
                  <tr>
                    <td colSpan={6}>
                      {ready
                        ? "No matching certificates. Select sources and collect them, or change the search."
                        : "Loading sources…"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <CertificatePagination page={page} size={pageSize} total={total} disabled={busy || !query}
            onPage={(target) => query && void run({ ...query, cursor: undefined, offset: (target - 1) * pageSize })}
            onSize={(size) => {
              if (query) void run({ ...query, cursor: undefined, offset: 0, limit: size });
            }} />
          <CertificateBatchControls total={total} key={selectionScope} selected={checkedCertificates} onSelection={setCheckedCertificates} query={query} disabled={busy}
            onChanged={() => { if (query) void run(query); }} />
        </>
      )}
      {tab === "sources" && (
        <>
          <div className="pki-box">
            <h2>Authorized PKI sources</h2>
            <p className="pki-muted">
              Selection changes the view and the next collection scope. Stored
              records remain in the catalog. Selection is saved for this browser
              tab and checked against current access. A complete observation
              covers stored, listed certificates only; no_store certificates are
              absent.
            </p>
            <div className="pki-table">
              <table>
                <thead>
                  <tr>
                    <th>Include</th>
                    <th>Mount / namespace</th>
                    <th>Coverage</th>
                    <th>Records / last collection</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Include ${s.path}`}
                          checked={selected.includes(s.id)}
                          onChange={(e) =>
                            setSelected(
                              e.target.checked
                                ? [...selected, s.id]
                                : selected.filter((id) => id !== s.id),
                            )
                          }
                        />
                      </td>
                      <td>
                        {s.path}
                        <small>{s.namespace || "root namespace"}</small>
                        <details>
                          <summary>Source identity</summary>
                          <small>
                            Cluster: {s.cluster}
                            <br />
                            Accessor: {s.accessor}
                          </small>
                        </details>
                      </td>
                      <td>
                        {s.coverage.replace(/_/g, " ")}
                        <small>
                          {coverageText[s.coverage] ||
                            "Observation incomplete; inspect the collection job."}
                        </small>
                      </td>
                      <td>
                        {s.certificateCount ?? 0}
                        <small>{s.lastCollected || "Never collected"}</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!sources.length && (
              <p>No PKI mounts with certificate-list access were discovered.</p>
            )}
          </div>
          <div className="pki-row">
            <button
              className="pki-primary"
              onClick={() => {
                setTab("inventory");
                search();
              }}
            >
              Apply selection
            </button>
            <button
              onClick={() =>
                void api
                  .pkiSources()
                  .then((r) => acceptSources(r.sources))
                  .catch((e) => setError(message(e)))
              }
            >
              Refresh sources
            </button>
          </div>
        </>
      )}
      {tab === "jobs" && (
        <>
          <p className="pki-muted pki-controls">
            Collections run in a separate process. Resume uses your current
            Vault session. Resume retries failed and pending items and rereads
            completed certificates to refresh revocation and identity evidence.
            Pausing finishes at a safe request boundary. Only one collection can
            be active.
          </p>
          {jobs.map((j) => (
            <section className="pki-box" key={j.id}>
              <div className="pki-row pki-spread">
                <h2>{j.status}</h2>
                <span>{j.createdAt}</span>
              </div>
              <p>
                {j.sources
                  .map((id) => sources.find((s) => s.id === id)?.path ?? id)
                  .join(", ")}
              </p>
              <p className="pki-controls">
                {j.completed.toLocaleString()} / {j.total.toLocaleString()}{" "}
                processed · {j.failed} failed
              </p>
              {j.error && <p className="pki-muted">{j.error}</p>}
              <div className="pki-row">
                <button
                  aria-expanded={expandedJob === j.id}
                  onClick={() =>
                    setExpandedJob(expandedJob === j.id ? null : j.id)
                  }
                >
                  Source progress and errors
                </button>
                {["queued", "running"].includes(j.status) && (
                  <button
                    disabled={actionBusy}
                    onClick={() => void jobAction(j.id, "pause")}
                  >
                    Pause
                  </button>
                )}
                {["paused", "partial", "interrupted"].includes(j.status) && (
                  <button
                    disabled={actionBusy}
                    onClick={() => void jobAction(j.id, "resume")}
                  >
                    Resume
                  </button>
                )}
              </div>
              {expandedJob === j.id && (
                <CollectionProgress id={j.id} updatedAt={j.updatedAt} />
              )}
            </section>
          ))}
          {!jobs.length && (
            <div className="pki-box">No collection jobs yet.</div>
          )}
        </>
      )}
    </div>
  );
}
