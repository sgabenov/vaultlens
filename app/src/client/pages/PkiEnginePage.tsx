import { useEffect, useState } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { AxiosError } from "axios";
import * as api from "../lib/api";
import { pkiEngineUrl, type PkiEngineResult } from "../../shared/pkiEngine";
import type { PkiSource } from "../../shared/pki";
import "../components/pki/pki.css";
const errorText = (e: unknown) =>
  e instanceof AxiosError
    ? e.response?.data?.error || e.message
    : e instanceof Error
      ? e.message
      : "Request failed";
const text = (value: unknown) =>
  value === null || value === undefined
    ? "Not set"
    : typeof value === "object"
      ? JSON.stringify(value, null, 2)
      : String(value);
function Properties({ data }: { data: Record<string, unknown> }) {
  return (
    <dl className="pki-detail-grid">
      {Object.entries(data)
        .filter(([key]) => !["certificate", "ca_chain"].includes(key))
        .map(([key, value]) => (
          <div key={key}>
            <dt>{key.replace(/_/g, " ")}</dt>
            <dd>{text(value)}</dd>
          </div>
        ))}
    </dl>
  );
}
export default function PkiEnginePage() {
  const navigate = useNavigate();
  const mount = useParams()["*"] || "",
    [params] = useSearchParams(),
    queryString = params.toString();
  const section = params.get("certificate")
    ? "certificate"
    : params.get("tab") || "overview";
  const ref =
    section === "certificate"
      ? params.get("certificate") || ""
      : params.get("ref") || "";
  const expected = params.get("source") || undefined,
    offset = Number(params.get("offset") || 0);
  const [source, setSource] = useState<PkiSource | null>(null),
    [result, setResult] = useState<PkiEngineResult | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [serial, setSerial] = useState("");
  const [cached, setCached] = useState<Awaited<
    ReturnType<typeof api.pkiCertificate>
  > | null>(null);
  useEffect(() => {
    let active = true;
    setSource(null);
    setResult(null);
    setCached(null);
    setError("");
    setLoading(true);
    setSerial(ref);
    void (async () => {
      try {
        const overview = await api.pkiEngine(
          mount,
          "overview",
          undefined,
          expected,
        );
        if (!active) return;
        setSource(overview.source);
        if (section === "overview") {
          setResult(overview);
          return;
        }
        if (section === "certificate") {
          const record = params.get("record");
          const [live, snapshot] = await Promise.allSettled([
            api.pkiEngine(mount, section, ref, overview.source.id),
            record ? api.pkiCertificate(Number(record)) : Promise.resolve(null),
          ]);
          if (!active) return;
          if (live.status === "fulfilled") setResult(live.value);
          else setError(errorText(live.reason));
          if (snapshot.status === "fulfilled" && snapshot.value) {
            const c = snapshot.value.certificate;
            const normalized = ref
              .replace(/[:-]/g, "")
              .toLowerCase()
              .replace(/^0+(?=.)/, "");
            if (c.sourceId === overview.source.id && c.serial === normalized)
              setCached(snapshot.value);
          }
        } else {
          const r = await api.pkiEngine(
            mount,
            section,
            ref || undefined,
            overview.source.id,
            offset,
          );
          if (active) setResult(r);
        }
      } catch (e) {
        if (active) setError(errorText(e));
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [mount, queryString]);
  const url = (values: Record<string, string | number | undefined> = {}) =>
    pkiEngineUrl(mount, { source: source?.id || expected, ...values });
  const cert = result?.certificate ?? cached?.certificate,
    pem = result?.pem ?? cached?.pem;
  function download() {
    if (!pem) return;
    const href = URL.createObjectURL(
      new Blob([pem], { type: "application/x-pem-file" }),
    );
    const a = document.createElement("a");
    a.href = href;
    a.download = (cert?.serial || "certificate") + ".pem";
    a.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  return (
    <div className="pki-workspace">
      <p>
        <Link to="/secrets">Secrets Engines</Link> /{" "}
        <Link to={url()}>{mount}</Link>
      </p>
      <h1>PKI · {mount}</h1>
      <p className="pki-muted">
        {source?.namespace || "Root namespace"} ·{" "}
        {source?.description || "Public key infrastructure"}
      </p>
      <nav className="pki-tabs" aria-label="PKI engine sections">
        {["overview", "issuers", "roles", "certificates"].map((tab) => (
          <Link
            key={tab}
            aria-current={section === tab ? "page" : undefined}
            to={url({ tab })}
          >
            {tab[0].toUpperCase() + tab.slice(1)}
          </Link>
        ))}
      </nav>
      {loading && <p role="status">Reading PKI engine…</p>}
      {error && (
        <div className="pki-error" role="alert">
          {error}
          {cached && (
            <p>
              The monitoring observation is shown below. It is not a successful
              live Vault read.
            </p>
          )}
        </div>
      )}
      {section === "overview" && source && (
        <section className="pki-box">
          <h2>Engine overview</h2>
          <Properties
            data={{
              mount: source.path,
              namespace: source.namespace || "root",
              cluster: source.cluster,
              accessor: source.accessor,
            }}
          />
          <p>
            Browse issuers, role definitions and stored certificate serials
            using your current Vault session. Each operation uses its own Vault
            permissions.
          </p>
          <Link to={"/certificates?mount=" + encodeURIComponent(mount)}>
            Open certificate monitoring for this mount
          </Link>
        </section>
      )}
      {section === "certificates" && (
        <form
          className="pki-box"
          action={url()}
          onSubmit={(e) => {
            e.preventDefault();
            if (serial.trim()) navigate(url({ certificate: serial.trim() }));
          }}
        >
          <label>
            Open certificate by serial{" "}
            <input
              aria-label="Certificate serial"
              value={serial}
              onChange={(e) => setSerial(e.target.value)}
              placeholder="Serial number"
            />
          </label>{" "}
          <button type="submit" disabled={!serial.trim()}>
            Open certificate
          </button>
          <p className="pki-muted">
            Vault lists stored serials only. Certificates issued with no_store,
            or removed by tidy, may still have a retained monitoring
            observation.
          </p>
          <Link to={"/certificates?mount=" + encodeURIComponent(mount)}>
            Search monitored certificates
          </Link>
        </form>
      )}
      {["roles", "issuers"].includes(section) && (
        <form
          className="pki-box"
          onSubmit={(e) => {
            e.preventDefault();
            if (serial.trim())
              navigate(url({ tab: section, ref: serial.trim() }));
          }}
        >
          <label>
            Open {section === "roles" ? "role by name" : "issuer by name or ID"}{" "}
            <input
              aria-label="PKI object reference"
              value={serial}
              onChange={(e) => setSerial(e.target.value)}
            />
          </label>{" "}
          <button type="submit" disabled={!serial.trim()}>
            Open {section === "roles" ? "role" : "issuer"}
          </button>
        </form>
      )}
      {result?.items && (
        <section className="pki-box">
          <h2>
            {section[0].toUpperCase() + section.slice(1)} · {result.total}
          </h2>
          {result.notice && <p role="status">{result.notice}</p>}
          {!result.items.length && <p>No entries returned.</p>}
          <div className="pki-table">
            <table>
              <thead>
                <tr>
                  <th>{section === "certificates" ? "Serial" : "Name / ID"}</th>
                  {section === "issuers" && <th>Issuer information</th>}
                </tr>
              </thead>
              <tbody>
                {result.items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <Link
                        to={
                          section === "certificates"
                            ? url({ certificate: item.id })
                            : url({ tab: section, ref: item.id })
                        }
                      >
                        {item.id}
                      </Link>
                    </td>
                    {section === "issuers" && <td>{text(item.info)}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pki-row pki-spread">
            {offset > 0 && (
              <Link
                to={url({ tab: section, offset: Math.max(0, offset - 50) })}
              >
                Previous
              </Link>
            )}
            {result.nextOffset !== null && result.nextOffset !== undefined && (
              <Link to={url({ tab: section, offset: result.nextOffset })}>
                Next
              </Link>
            )}
          </div>
        </section>
      )}
      {result?.data && (
        <section className="pki-box">
          <h2>
            {section === "roles" ? "Role" : "Issuer"} · {ref}
          </h2>
          {section === "roles" && (
            <>
              <p>
                Configured issuer:{" "}
                <Link
                  to={url({
                    tab: "issuers",
                    ref: String(result.data.issuer_ref || "default"),
                  })}
                >
                  {String(result.data.issuer_ref || "default")}
                </Link>
              </p>
              <p className="pki-muted">
                This is the current role configuration. It does not prove which
                existing certificates were issued through this role.
              </p>
            </>
          )}
          <Properties data={result.data} />
          {typeof result.data.certificate === "string" && (
            <details>
              <summary>Issuer certificate PEM</summary>
              <pre>{result.data.certificate}</pre>
            </details>
          )}
          {Array.isArray(result.data.ca_chain) && (
            <details>
              <summary>CA chain</summary>
              <pre>{result.data.ca_chain.join("\n")}</pre>
            </details>
          )}
        </section>
      )}
      {section === "certificate" && cert && (
        <section className="pki-box pki-detail">
          <h2>{cert.cn || cert.serial}</h2>
          <p>
            <strong>
              {cert.notAfter <= Date.now()
                ? "Expired"
                : cert.notBefore > Date.now()
                  ? "Not yet valid"
                  : "Valid"}
            </strong>{" "}
            · {result?.certificate ? "Live Vault read" : "Monitoring snapshot"}
          </p>
          {result?.certificate &&
            cached &&
            result.certificate.fingerprint !==
              cached.certificate.fingerprint && (
              <p className="pki-error">
                Identity conflict: the live certificate differs from the
                retained monitoring observation. The original observation has
                not been replaced.
              </p>
            )}
          <Properties
            data={{
              serial: cert.serial,
              fingerprint: cert.fingerprint,
              subject: cert.subject,
              issuer: cert.issuer,
              valid_from: new Date(cert.notBefore).toISOString(),
              expires_at: new Date(cert.notAfter).toISOString(),
              usage: cert.type,
              revocation: result?.revocation ?? cached?.certificate.revoked,
              observed_at: result?.observedAt ?? cached?.certificate.lastSeen,
              sans: cert.sans,
              role: "Unknown: no issuance evidence",
            }}
          />
          {result?.issuer?.ref && (
            <p>
              <Link to={url({ tab: "issuers", ref: result.issuer.ref })}>
                View verified signing issuer
              </Link>
            </p>
          )}
          <p className="pki-muted">
            Issuer evidence: {result?.issuerState ?? cached?.issuerState}.
            Signature verification is not a complete trust-chain verdict.
          </p>
          <div className="pki-row">
            <button onClick={download}>Download PEM</button>
            <Link
              to={
                "/certificates?filter=" +
                encodeURIComponent(
                  JSON.stringify({
                    sources: [source!.id],
                    conditions: [
                      {
                        field: "serial",
                        operator: "equals",
                        value: cert.serial,
                      },
                    ],
                    match: "all",
                    sort: "notAfter",
                    direction: "asc",
                    limit: 50,
                  }),
                )
              }
            >
              Find in Certificates monitoring
            </Link>
          </div>
          <details>
            <summary>Certificate PEM</summary>
            <pre>{pem}</pre>
          </details>
          {cached && (
            <details>
              <summary>Retained monitoring observation</summary>
              <Properties
                data={{
                  fingerprint: cached.certificate.fingerprint,
                  last_observed: cached.certificate.lastSeen,
                  revocation: cached.certificate.revoked,
                  presence: cached.certificate.presence,
                }}
              />
              <pre>{cached.pem}</pre>
            </details>
          )}
        </section>
      )}
    </div>
  );
}
