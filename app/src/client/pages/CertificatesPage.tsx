import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AxiosError } from "axios";
import * as api from "../lib/api";
import type {
  CertificateRecord,
  PkiCondition,
  PkiJob,
  PkiQuery,
  PkiSource,
} from "../../shared/pki";
import { pkiSearchFields } from "../../shared/pki";
import CertificateSearch from "../components/pki/CertificateSearch";
import "../components/pki/pki.css";
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
  const [rows, setRows] = useState<CertificateRecord[]>([]),
    [total, setTotal] = useState(0),
    [next, setNext] = useState<string | null>(null),
    [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
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
  const initialParams = useRef(params.toString());
  async function run(q: PkiQuery) {
    const gen = ++generation.current;
    setBusy(true);
    setError("");
    setDetail(null);
    detailGeneration.current++;
    try {
      const r = await api.pkiQuery(q);
      if (gen !== generation.current) return;
      setRows(r.certificates);
      setTotal(r.total);
      setNext(r.nextCursor);
      setQuery(q);
    } catch (e) {
      if (gen === generation.current) {
        setError(message(e));
        setRows([]);
        setTotal(0);
        setNext(null);
      }
    } finally {
      if (gen === generation.current) setBusy(false);
    }
  }
  useEffect(() => {
    let cancelled = false;
    void api
      .pkiSources()
      .then((r) => {
        if (cancelled) return;
        setSources(r.sources);
        const p = new URLSearchParams(initialParams.current);
        const scoped = p.get("mount");
        let restored: Partial<PkiQuery> = {};
        try {
          const raw = p.get("filter");
          if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
              restored = parsed;
          }
        } catch {
          /* Invalid shared query falls back to the source picker. */
        }
        const ids = Array.isArray(restored.sources)
          ? r.sources
              .filter((s) => restored.sources!.includes(s.id))
              .map((s) => s.id)
          : r.sources
              .filter((s) => !scoped || s.path === scoped.replace(/\/$/, ""))
              .map((s) => s.id);
        setSelected(ids);
        setReady(true);
        const q: PkiQuery = {
          sources: ids,
          conditions: [],
          match: "all",
          sort: "notAfter",
          direction: "asc",
          limit: 50,
          ...restored,
        };
        q.sources = ids;
        q.cursor = undefined;
        // Server validates the shared search. Do not use arbitrary URL fields to render controls.
        if (
          !Array.isArray(q.conditions) ||
          !q.conditions.every(
            (c) =>
              c &&
              Object.prototype.hasOwnProperty.call(pkiSearchFields, c.field) &&
              pkiSearchFields[c.field].operators.includes(c.operator) &&
              typeof c.value === "string",
          )
        )
          q.conditions = [];
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
  }, []);
  useEffect(() => {
    if (tab !== "jobs") return;
    let active = true;
    const load = () => {
      if (document.visibilityState === "hidden") return;
      void api
        .pkiJobs()
        .then((r) => {
          if (active) setJobs(r.jobs);
        })
        .catch((e) => {
          if (active) setError(message(e));
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
      limit: 50,
    };
    setCursors([undefined]);
    setParams({ filter: JSON.stringify(q) }, { replace: true });
    void run(q);
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
    try {
      await api.pkiJobAction(id, action);
      setJobs((await api.pkiJobs()).jobs);
    } catch (e) {
      setError(message(e));
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
      .then((r) => setSources(r.sources))
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
          <div className="pki-row pki-spread">
            <span className="pki-muted">
              {selected.length} sources selected ·{" "}
              {
                sources.filter(
                  (s) => selected.includes(s.id) && s.coverage === "complete",
                ).length
              }{" "}
              completely collected
            </span>
            <button
              disabled={busy || !query}
              onClick={() => query && void run(query)}
            >
              Refresh results
            </button>
          </div>
          <div className="pki-row pki-controls">
            <button onClick={() => setTab("sources")}>
              Sources · {selected.length}
            </button>
            <label>
              Type{" "}
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
          </div>
          <CertificateSearch
            conditions={conditions}
            onChange={setConditions}
            match={match}
            onMatch={setMatch}
            onSearch={search}
            disabled={busy || !ready}
          />
          {detail && (
            <section
              className="pki-box pki-detail"
              aria-label="Certificate details"
            >
              <div className="pki-row pki-spread">
                <h2>{detail.certificate.cn || detail.certificate.serial}</h2>
                <button
                  onClick={() => {
                    setDetail(null);
                    detailGeneration.current++;
                  }}
                >
                  Close
                </button>
              </div>
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
              <div className="pki-row">
                <button onClick={downloadPem}>Download PEM</button>
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
            </section>
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
          <div className="pki-box pki-table">
            <table>
              <thead>
                <tr>
                  <th>Common name / serial</th>
                  <th>Source / type</th>
                  <th>Validity</th>
                  <th>Revocation</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <button className="pki-link" onClick={() => void open(c)}>
                        {c.cn || "(no common name)"}
                      </button>
                      <small>{c.serial}</small>
                    </td>
                    <td>
                      {c.sourcePath}
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
                  </tr>
                ))}
                {!rows.length && (
                  <tr>
                    <td colSpan={4}>
                      {ready
                        ? "No matching certificates. Select sources and collect them, or change the search."
                        : "Loading sources…"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="pki-row pki-spread">
            <span className="pki-muted">
              Page {cursors.length} · up to 50 records
            </span>
            <div className="pki-row">
              <button
                disabled={busy || cursors.length === 1}
                onClick={() => {
                  const stack = cursors.slice(0, -1);
                  setCursors(stack);
                  if (query) void run({ ...query, cursor: stack.at(-1) });
                }}
              >
                Previous
              </button>
              <button
                disabled={busy || !next}
                onClick={() => {
                  setCursors([...cursors, next!]);
                  if (query) void run({ ...query, cursor: next! });
                }}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
      {tab === "sources" && (
        <>
          <div className="pki-box">
            <h2>Authorized PKI sources</h2>
            <p className="pki-muted">
              Selection changes the view and the next collection scope. Stored
              records remain in the catalog.
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
                      </td>
                      <td>{s.coverage.replace(/_/g, " ")}</td>
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
                  .then((r) => setSources(r.sources))
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
            Vault session.
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
                {["queued", "running"].includes(j.status) && (
                  <button onClick={() => void jobAction(j.id, "pause")}>
                    Pause
                  </button>
                )}
                {["paused", "partial", "interrupted"].includes(j.status) && (
                  <button onClick={() => void jobAction(j.id, "resume")}>
                    Resume
                  </button>
                )}
              </div>
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
