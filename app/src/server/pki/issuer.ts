import { X509Certificate } from "node:crypto";
import { PkiAdapter } from "./adapter.js";
import type { PkiSource } from "../../shared/pki.js";
export async function findIssuer(
  pem: string,
  source: PkiSource,
  adapter: PkiAdapter,
) {
  const leaf = new X509Certificate(pem);
  const matches = (candidate: X509Certificate) =>
    candidate.ca &&
    leaf.checkIssued(candidate) &&
    leaf.verify(candidate.publicKey);
  if (matches(leaf))
    return { issuer: { pem, subject: leaf.subject }, issuerState: "verified" };
  let candidates: string[] = [];
  try {
    const keys = (await adapter.request(source.path + "/issuers", "LIST")).data
      ?.keys;
    if (Array.isArray(keys) && keys.every((k) => typeof k === "string"))
      candidates = keys;
  } catch {
    /* Older mounts may expose only the default CA. */
  }
  if (candidates.length > 100)
    return { issuer: null, issuerState: "too_many_issuers" };
  let unavailable = false;
  for (const ref of candidates.length ? candidates : ["default"]) {
    try {
      const certificate =
        ref === "default"
          ? await adapter.pem(source, "ca")
          : (
              await adapter.request(
                source.path + "/issuer/" + encodeURIComponent(ref),
                "GET",
                undefined,
                1024 * 1024,
              )
            ).data.certificate;
      const ca = new X509Certificate(certificate);
      if (matches(ca))
        return {
          issuer: { pem: certificate as string, subject: ca.subject },
          issuerState: "verified",
        };
    } catch {
      unavailable = true;
    }
  }
  return {
    issuer: null,
    issuerState: unavailable ? "unavailable" : "unresolved",
  };
}
