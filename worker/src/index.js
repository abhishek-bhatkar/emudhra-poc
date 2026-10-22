import tls from "node:tls";
import crypto from "node:crypto";
import { Agent } from "cloudflare:sockets";

// GET /chain?host=example.com[&port=443]
// TLS-connects, returns the SPKI SHA-256 of every cert in the served chain.
// Facts only. The page computes the verdict.
export default {
  async fetch(req) {
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    };
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "GET") return json({ error: "GET only" }, 405, cors);

    const { searchParams } = new URL(req.url);
    const host = searchParams.get("host") || "";
    const port = Number(searchParams.get("port")) || 443;
    // Hostnames only. Anything wilder smuggles SNI bytes or proxy targets.
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host))
      return json({ error: "bad host" }, 400, cors);
    if (port < 1 || port > 65535) return json({ error: "bad port" }, 400, cors);

    let socket;
    try {
      socket = await connectTLS(host, port);
      const chain = collect(socket.getPeerCertificate(true));
      return json({ host, chain }, 200, cors);
    } catch (e) {
      return json({ host, error: String((e && e.message) || e) }, 502, cors);
    } finally {
      try { socket && socket.destroy(); } catch {}
    }
  },
};

function connectTLS(host, port) {
  return new Promise((resolve, reject) => {
    let s;
    s = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,  // we want the chain exactly as served; verdicts are not this worker's job
        socket: new Agent({ hostname: host, port }),
        agent: false,
      },
      () => resolve(s),
    );
    s.setTimeout(15000, () => s.destroy(new Error("tls timeout")));
    s.on("error", reject);
    s.on("tlsClientError", reject);
  });
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors } });
}

// getPeerCertificate(true) returns a linked list through issuerCertificate.
// Node's `pubkey` field is the bare key point, not SPKI DER, so SPKIs come from
// X509Certificate(der).publicKey.export({ type: "spki", format: "der" }).
function collect(certs) {
  const seen = new Set();
  const out = [];
  let c = certs;
  while (c && c.raw) {
    const der = Buffer.from(c.raw);
    const id = der.toString("base64");
    if (!seen.has(id)) {
      seen.add(id);
      let spki = null;
      try {
        const x509 = new crypto.X509Certificate(der);
        spki = crypto.createHash("sha256")
          .update(x509.publicKey.export({ type: "spki", format: "der" }))
          .digest("hex");
      } catch {}
      out.push({
        spki_sha256: spki,
        subject_cn: cnOf(c.subject),
      });
    }
    c = c.issuerCertificate !== c ? c.issuerCertificate : null;
  }
  return out;
}

function cnOf(subject) {
  if (!subject) return "";
  const cn = subject.CN;
  if (Array.isArray(cn)) return cn[0] || "";
  return cn || "";
}
