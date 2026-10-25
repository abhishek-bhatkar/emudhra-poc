import { connect } from "cloudflare:sockets";
import crypto from "node:crypto";

const PROBE_BUDGET_MS = 15000;
const PROBE_ATTEMPT_MS = 5000;
const DNS_LOOKUP_MS = 3000;
const MAX_TLS_RECORD_LENGTH = 18432;
const MAX_HANDSHAKE_BYTES = 256 * 1024;
const MAX_DOH_ADDRESSES = 8;

class TcpConnectError extends Error {}
class ProbeTimeoutError extends Error {}

// GET /chain?host=example.com[&port=443]
// TLS-connects to the host and returns the SPKI SHA-256 of every cert in the
// served chain. Facts only; the page computes the verdict.
//
// The runtime's node:tls cannot expose certificate bytes (getPeerCertificate
// is not implemented), so this worker drives the handshake itself over a raw
// TCP socket. Only TLS 1.2 is spoken, and the job ends the moment the
// Certificate message is read: the chain before key exchange is plaintext, so
// no key exchange, secrets, or decryption are involved. X509Certificate is
// used offline on the collected DER, and one mismatched SPKI leaf (like bare
// EC points) cannot sneak past that export path. Hosts that refuse TLS 1.2
// come back as an error, and the page shows UNKNOWN rather than any green.

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const originHeader = req.headers.get("Origin");
    const allowedOrigins = new Set(
      (env.ALLOWED_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean),
    );
    const origin = originHeader && allowedOrigins.has(originHeader) ? originHeader : null;

    if (originHeader && !origin) return json({ error: "origin not allowed" }, 403, null);
    if (url.pathname !== "/chain") return json({ error: "not found" }, 404, origin);
    if (req.method === "OPTIONS") return preflight(origin);
    if (req.method !== "GET") return json({ error: "GET only" }, 405, origin);

    const parsed = parseProbeQuery(url);
    if (parsed.error) return json({ error: parsed.error }, 400, origin);
    const { host, port } = parsed;

    const limitState = await checkRateLimit(req, env);
    if (limitState === "limited")
      return json({ error: "rate limited" }, 429, origin, { "Retry-After": "60" });
    if (limitState === "unavailable")
      return json({ error: "rate limiter unavailable" }, 503, origin);

    try {
      const certs = await probeWithDnsFallback(host, port, PROBE_BUDGET_MS);
      const chain = certs.map((der) => {
        const x509 = new crypto.X509Certificate(der);
        const spki = crypto.createHash("sha256")
          .update(x509.publicKey.export({ type: "spki", format: "der" }))
          .digest("hex");
        const cn = x509.subject.split("\n").find((line) => line.startsWith("CN="))?.slice(3) || "";
        return { spki_sha256: spki, subject_cn: cn };
      });
      return json({ host, port, chain }, 200, origin, {
        "Cache-Control": "public, max-age=60, stale-if-error=0",
      });
    } catch (error) {
      return json({ host, port, error: errorMessage(error) }, 502, origin);
    }
  },
};

function corsHeaders(origin) {
  const headers = {
    "Vary": "Origin",
    "Content-Type": "application/json",
  };
  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "GET, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type";
  }
  return headers;
}

function preflight(origin) {
  const headers = corsHeaders(origin);
  headers["Access-Control-Max-Age"] = "86400";
  headers["Cache-Control"] = "no-store";
  return new Response(null, { status: 204, headers });
}

function json(obj, status, origin, extra = {}) {
  return new Response(JSON.stringify({ ok: status >= 200 && status < 300, ...obj }), {
    status,
    headers: { ...corsHeaders(origin), "Cache-Control": "no-store", ...extra },
  });
}

function parseProbeQuery(url) {
  const allowedParams = new Set(["host", "port"]);
  for (const key of url.searchParams.keys()) {
    if (!allowedParams.has(key)) return { error: "unexpected query parameter" };
  }

  const hosts = url.searchParams.getAll("host");
  const ports = url.searchParams.getAll("port");
  if (hosts.length !== 1) return { error: "provide one host" };
  if (ports.length > 1) return { error: "provide one port" };

  const host = hosts[0].toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || host.includes(":") || isIpLiteral(host))
    return { error: "host must be a DNS name; IP literals are not supported" };
  if (host.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host))
    return { error: "host must be a fully qualified DNS name" };

  let port = 443;
  if (ports.length) {
    if (!/^\d{1,5}$/.test(ports[0])) return { error: "bad port" };
    port = Number(ports[0]);
    if (port < 1 || port > 65535) return { error: "bad port" };
  }
  return { host, port };
}

function isIpLiteral(host) {
  try {
    const normalized = new URL("https://" + host + "/").hostname;
    return normalized.includes(":") || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(normalized);
  } catch {
    return true;
  }
}

async function checkRateLimit(req, env) {
  const ip = req.headers.get("CF-Connecting-IP");
  if (!ip || !env.CHAIN_RATE_LIMITER) return "unavailable";
  try {
    const { success } = await env.CHAIN_RATE_LIMITER.limit({ key: ip });
    return success ? "allowed" : "limited";
  } catch {
    return "unavailable";
  }
}

function errorMessage(error) {
  return String((error && error.message) || error);
}

async function probeWithDnsFallback(host, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let hostnameError;
  const withHostnameFailure = (detail) =>
    "hostname probe failed: " + errorMessage(hostnameError) + "; " + detail;
  try {
    return await probe(host, port, Math.min(remainingMs(deadline), PROBE_ATTEMPT_MS), host);
  } catch (error) {
    if (!(error instanceof TcpConnectError)) throw error;
    hostnameError = error;
  }

  let addresses;
  try {
    addresses = await resolveA(host, Math.min(remainingMs(deadline), DNS_LOOKUP_MS));
  } catch (error) {
    if (error instanceof ProbeTimeoutError) throw error;
    throw new Error(withHostnameFailure("A-record lookup failed: " + errorMessage(error)));
  }
  if (!addresses.length)
    throw new Error(withHostnameFailure("no public A record found"));

  const connectErrors = [];
  for (const ip of addresses) {
    try {
      return await probe(ip, port, Math.min(remainingMs(deadline), PROBE_ATTEMPT_MS), host);
    } catch (error) {
      if (error instanceof ProbeTimeoutError) throw error;
      if (!(error instanceof TcpConnectError)) {
        throw new Error(withHostnameFailure("resolved-IP TLS probe failed: " + errorMessage(error)));
      }
      connectErrors.push(ip + ": " + errorMessage(error));
      if (Date.now() >= deadline) throw new ProbeTimeoutError("probe timed out");
    }
  }
  throw new Error(withHostnameFailure("resolved-IP connects failed: " + connectErrors.join("; ")));
}

function remainingMs(deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new ProbeTimeoutError("probe timed out");
  return remaining;
}

async function resolveA(host, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(host) + "&type=A",
      { headers: { accept: "application/dns-json" }, signal: controller.signal });
    if (!response.ok) throw new Error("DNS lookup returned HTTP " + response.status);
    const result = await response.json();
    return [...new Set((result.Answer || [])
      .filter((answer) => answer.type === 1 && isPublicIPv4(answer.data))
      .map((answer) => answer.data))]
      .slice(0, MAX_DOH_ADDRESSES);
  } catch (error) {
    if (controller.signal.aborted) throw new ProbeTimeoutError("DNS lookup timed out");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function isIPv4(address) {
  const octets = String(address || "").split(".");
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet)
    && Number(octet) >= 0 && Number(octet) <= 255);
}

function isPublicIPv4(address) {
  if (!isIPv4(address)) return false;
  const [first, second, third] = address.split(".").map(Number);
  return first !== 0 && first !== 10 && first !== 127
    && !(first === 100 && second >= 64 && second <= 127)
    && !(first === 169 && second === 254)
    && !(first === 172 && second >= 16 && second <= 31)
    && !(first === 192 && second === 0 && third === 0)
    && !(first === 192 && second === 0 && third === 2)
    && !(first === 192 && second === 88 && third === 99)
    && !(first === 192 && second === 168)
    && !(first === 198 && (second === 18 || second === 19))
    && !(first === 198 && second === 51 && third === 100)
    && !(first === 203 && second === 0 && third === 113)
    && first < 224;
}

// Open TCP, send a TLS 1.2 ClientHello, reassemble the handshake stream, and
// return the raw DER certificates from the Certificate message.
// target may be a hostname or an IP; sni is the ServerName to present.
async function probe(target, port, timeoutMs, sni) {
  let socket;
  try {
    socket = connect({ hostname: target, port }, { allowHalfOpen: true });
  } catch (error) {
    throw new TcpConnectError("tcp connect failed: " + errorMessage(error));
  }
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let timedOut = false;
  const dead = setTimeout(() => {
    timedOut = true;
    try { socket.close(); } catch {}
  }, timeoutMs);

  try {
    try {
      await socket.opened;
    } catch (error) {
      if (timedOut) throw new TcpConnectError("tcp connect timed out");
      throw new TcpConnectError("tcp connect failed: " + errorMessage(error));
    }
    if (timedOut) throw new TcpConnectError("tcp connect timed out");
    try {
      await writer.write(clientHello(sni));
    } catch (error) {
      if (timedOut) throw new ProbeTimeoutError("probe timed out");
      throw new Error("TLS write failed: " + errorMessage(error));
    }

    let hsBuf = new Uint8Array(0);
    let recBuf = new Uint8Array(0);   // incomplete TLS record bytes
    while (true) {
      let rec;
      try { rec = await reader.read(); } catch (error) {
        if (timedOut) throw new ProbeTimeoutError("probe timed out");
        throw new Error("tls read failed: " + errorMessage(error));
      }
      if (rec.done) {
        if (timedOut) throw new ProbeTimeoutError("probe timed out");
        throw new Error("connection closed before certificate");
      }
      const chunk = rec.value instanceof Uint8Array ? rec.value : new Uint8Array(rec.value);
      if (recBuf.length + chunk.length > MAX_HANDSHAKE_BYTES + MAX_TLS_RECORD_LENGTH)
        throw new Error("TLS input exceeds the size limit");
      const stream = recBuf.length ? concat(recBuf, chunk) : chunk;
      let off = 0;
      while (true) {
        if (stream.length - off < 5) break;          // header split across chunks
        const type = stream[off];
        const len = (stream[off + 3] << 8) | stream[off + 4];
        if (len > MAX_TLS_RECORD_LENGTH) throw new Error("TLS record exceeds the size limit");
        if (off + 5 + len > stream.length) break;    // body split across chunks
        if (type === 21) {
          if (len < 2) throw new Error("truncated TLS alert");
          const level = stream[off + 5];
          const description = stream[off + 6];
          const levelName = level === 1 ? "warning" : level === 2 ? "fatal" : "unknown level";
          const descriptionName = ({ 40: "handshake_failure", 70: "protocol_version" })[description] || "unknown alert";
          throw new Error("TLS alert " + levelName + " " + descriptionName
            + " (level " + level + ", description " + description + ")");
        }
        if (type === 22) {
          const fragment = stream.subarray(off + 5, off + 5 + len);
          if (hsBuf.length + fragment.length > MAX_HANDSHAKE_BYTES)
            throw new Error("TLS handshake exceeds the size limit");
          hsBuf = concat(hsBuf, fragment);
        }
        off += 5 + len;
      }
      recBuf = stream.subarray(off);
      let pos = 0;
      while (pos + 4 <= hsBuf.length) {
        const mlen = (hsBuf[pos + 1] << 16) | (hsBuf[pos + 2] << 8) | hsBuf[pos + 3];
        if (pos + 4 + mlen > hsBuf.length) break;      // message continues in the next record
        if (hsBuf[pos] === 11) {
          const got = certList(hsBuf.subarray(pos + 4, pos + 4 + mlen));
          if (!got.length) throw new Error("no certificates in chain");
          return got;
        }
        pos += 4 + mlen;
      }
      hsBuf = hsBuf.subarray(pos);
    }
  } finally {
    clearTimeout(dead);
    try { writer.releaseLock(); } catch {}
    try { reader.releaseLock(); } catch {}
    try { socket.close(); } catch {}
  }
}

// Certificate message body = u24 listLen, then of [ u24 certLen, DER ]*
function certList(body) {
  if (body.length < 3) throw new Error("malformed certificate list");
  const listLen = (body[0] << 16) | (body[1] << 8) | body[2];
  const end = 3 + listLen;
  if (end !== body.length) throw new Error("truncated certificate list");

  const certs = [];
  let pos = 3;
  while (pos < end) {
    if (pos + 3 > end) throw new Error("truncated certificate length");
    const certLen = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2];
    pos += 3;
    if (certLen === 0 || pos + certLen > end) throw new Error("malformed certificate entry");
    certs.push(Buffer.from(body.subarray(pos, pos + certLen)));
    pos += certLen;
  }
  return certs;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

// Minimal TLS 1.2 ClientHello: SNI, eight common cipher suites, three groups,
// eight signature algorithms, and uncompressed EC points. server_name carries
// one hostname.
function clientHello(host) {
  const name = ascii(host);
  // server_name extension body: u16 listLen(3+name), u8 nametype 0, u16 nameLen, name
  const sni = pack([u16(name.length + 3), [0], u16(name.length), name]);
  const suites = pack([0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0xc027, 0xc023].map(u16));
  const groups = pack([0x001d, 0x0017, 0x0018].map(u16));
  const sigalgs = pack([0x0401, 0x0403, 0x0501, 0x0503, 0x0804, 0x0805, 0x0402, 0x0601].map(u16));
  const extBytes = pack([
    ext(0x0000, sni),
    ext(0x000a, pack([u16(groups.length)]), groups),
    ext(0x000b, pack([[1], [0]])),
    ext(0x000d, pack([u16(sigalgs.length)]), sigalgs),
  ]);
  const exts = pack([u16(extBytes.length)], extBytes);

  const hello = pack([
    u16(0x0303),                                   // client_version = TLS 1.2
    crypto.getRandomValues(new Uint8Array(32)),    // random
    [0],                                           // session_id: none
    u16(suites.length), suites,
    [1, 0],                                        // compression: null only
    exts,
  ]);
  return record(22, pack([[1], u24(hello.length)], hello), 0x0301);
}

// TLS record: u8 type, u16 version, u16 len, body
function record(type, fragment, version) {
  return pack([[type], u16(version), u16(fragment.length)], fragment);
}

function ext(type, ...bodies) { return pack([u16(type), u16(sum(bodies))], ...bodies); }

function sum(bodies) { return bodies.reduce((total, body) => total + body.length, 0); }

function u16(value) { return [value >> 8, value & 0xff]; }
function u24(value) { return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]; }

function pack(...items) {
  const out = new Uint8Array(count(...items));
  let index = 0;
  const write = (...chunks) => {
    for (const chunk of chunks) {
      if (chunk instanceof Uint8Array) { out.set(chunk, index); index += chunk.length; }
      else if (Array.isArray(chunk)) write(...chunk);
      else out[index++] = chunk & 0xff;
    }
  };
  write(...items);
  return out;
}

function count(...items) {
  let length = 0;
  for (const chunk of items) {
    if (chunk instanceof Uint8Array) length += chunk.length;
    else if (Array.isArray(chunk)) length += count(...chunk);
    else length++;
  }
  return length;
}

function ascii(value) {
  const out = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code > 0x7f) throw new Error("SNI must be ASCII");
    out[index] = code;
  }
  return out;
}
