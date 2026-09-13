import {
  Router,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import { config } from "../config/index.js";
import { PkiAdapter, PkiError, scopePath } from "../pki/adapter.js";
import { normalizeSerial, parseCertificate } from "../pki/certificate.js";
import { findIssuer } from "../pki/issuer.js";
// Engine reads deliberately do not require certificate LIST access or a system token.
export const pkiEngineRouter = Router();
pkiEngineRouter.get(
  "/",
  async (req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      const token = req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.slice(7)
        : req.cookies?.vault_token;
      if (typeof token !== "string" || !token)
        throw new PkiError(401, "Authentication required");
      const adapter = new PkiAdapter(
        config.vaultAddr,
        token,
        process.env.VAULTLENS_PKI_NAMESPACE || "",
        config.vaultSkipTlsVerify,
      );
      await adapter.verifyToken();
      const mount = scopePath(String(req.query.mount || ""));
      const source = (await adapter.discover()).find((s) => s.path === mount);
      if (!source)
        throw new PkiError(
          404,
          "PKI mount not found or not visible to this session",
        );
      if (req.query.source && req.query.source !== source.id)
        throw new PkiError(
          409,
          "PKI mount identity changed; return to Secrets Engines",
        );
      const section = String(req.query.section || "overview"),
        ref = String(req.query.ref || "");
      if (
        ref &&
        (ref.length > 256 ||
          ref === "." ||
          ref === ".." ||
          /[\x00-\x1f\x7f/\\?#%]/.test(ref))
      )
        throw new PkiError(400, "Invalid PKI object reference");
      let result: unknown;
      if (section === "overview") result = { source };
      else if (
        section === "roles" ||
        section === "issuers" ||
        section === "certificates"
      ) {
        if (ref) {
          if (section === "certificates")
            throw new PkiError(400, "Use certificate lookup for a serial");
          const endpoint = section === "roles" ? "roles" : "issuer";
          result = {
            source,
            data: (
              await adapter.request(
                `${source.path}/${endpoint}/${encodeURIComponent(ref)}`,
                "GET",
                undefined,
                2 * 1024 * 1024,
              )
            ).data,
          };
        } else {
          const offset = Number(req.query.offset || 0);
          if (!Number.isSafeInteger(offset) || offset < 0)
            throw new PkiError(400, "Invalid offset");
          let data: { keys?: unknown; key_info?: Record<string, unknown> } = {};
          try {
            data = (
              await adapter.request(
                `${source.path}/${section === "certificates" ? "certs" : section}`,
                "LIST",
              )
            ).data;
          } catch (e) {
            if (!(e instanceof PkiError) || e.status !== 404) throw e;
            result = {
              source,
              items: [],
              total: 0,
              nextOffset: null,
              notice:
                "No entries returned; this endpoint may be unavailable on older mounts.",
            };
          }
          if (!result) {
            if (
              !Array.isArray(data?.keys) ||
              data.keys.some((k) => typeof k !== "string")
            )
              throw new PkiError(502, "Invalid PKI list response");
            const keys = data.keys as string[];
            result = {
              source,
              items: keys
                .slice(offset, offset + 50)
                .map((id) => ({ id, info: data.key_info?.[id] ?? null })),
              total: keys.length,
              nextOffset: offset + 50 < keys.length ? offset + 50 : null,
            };
          }
        }
      } else if (section === "certificate") {
        let serial: string;
        try {
          serial = normalizeSerial(ref);
        } catch {
          throw new PkiError(400, "Invalid certificate serial");
        }
        // Vault expects byte pairs; catalog serials omit leading zeroes and separators.
        const vaultSerial = (serial.length % 2 ? "0" + serial : serial)
          .match(/.{2}/g)!
          .join("-");
        const observation = await adapter.certificate(source, vaultSerial);
        const { der, ...certificate } = parseCertificate(observation.pem);
        if (certificate.serial !== serial)
          throw new PkiError(
            502,
            "Vault returned a different certificate serial",
          );
        const issuer = await findIssuer(observation.pem, source, adapter);
        result = {
          source,
          certificate,
          pem: observation.pem,
          revocation: observation.revocation,
          observedAt: new Date().toISOString(),
          ...issuer,
        };
      } else throw new PkiError(400, "Unsupported PKI engine section");
      // Reject a remount/replacement while an object was being read.
      const current = (await adapter.discover()).find(
        (s) => s.id === source.id && s.path === source.path,
      );
      if (!current)
        throw new PkiError(409, "PKI mount identity changed during the read");
      res.json(result);
    } catch (e) {
      next(e);
    }
  },
);
pkiEngineRouter.use(
  (e: unknown, _req: Request, res: Response, _next: NextFunction) =>
    res.status(e instanceof PkiError ? e.status : 500).json({
      error: e instanceof PkiError ? e.message : "PKI engine read failed",
    }),
);
export default pkiEngineRouter;
