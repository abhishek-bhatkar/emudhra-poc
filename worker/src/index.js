import { connect } from "cloudflare:sockets";
import crypto from "node:crypto";

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
    // Hostnames only. Anything wilder smuggles SNI bytes or odd ports.
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host))
      return json({ error: "bad host" }, 400, cors);
    if (port < 1 || port > 65535) return json({ error: "bad port" }, 400, cors);

    try {
      const certs = await servedChainFirst(host, port, 12000);
      const chain = certs.map((der) => {
        let spki = null;
        let cn = "";
        try {
          const x509 = new crypto.X509Certificate(der);
          spki = crypto.createHash("sha256")
            .update(x509.publicKey.export({ type: "spki", format: "der" }))
            .digest("hex");
          cn = x509.subject.split("\n").find((l) => l.startsWith("CN="))?.slice(3) || "";
        } catch {}
        return { spki_sha256: spki, subject_cn: cn };
      });
      return json({ host, chain }, 200, cors);
    } catch (e) {
      return json({ host, error: String((e && e.message) || e) }, 502, cors);
    }
  },
};

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors } });
}

// Try the hostname, then retry over DoH-resolved IP with the same SNI.
// Some names behave differently inside the runtime's socket path.
async function servedChainFirst(host, port, timeoutMs) {
  try {
    return await probe(host, port, timeoutMs, host);
  } catch (first) {
    let ip;
    try { ip = await resolveA(host); } catch {}
    if (!ip) throw first;
    try {
      return await probe(ip, port, timeoutMs, host);
    } catch (second) {
      throw new Error(String((first && first.message) || first) + " / " + String((second && second.message) || second));
    }
  }
}

async function resolveA(host) {
  const r = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(host) + "&type=A",
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  const a = (j.Answer || []).find((x) => x.type === 1 && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(x.data || ""));
  return a ? a.data : null;
}

// Open TCP, send a TLS 1.2 ClientHello, reassemble the handshake stream, and
// return the raw DER certificates from the Certificate message.
// target may be a hostname or an IP; sni is the ServerName to present.
async function probe(target, port, timeoutMs, sni) {
  const socket = connect({ hostname: target, port }, { allowHalfOpen: true });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const dead = setTimeout(() => { try { socket.close(); } catch {} }, timeoutMs);

  try {
    try {
      await socket.opened;
    } catch (e) {
      throw new Error("tcp connect failed: " + (e && e.message || e));
    }
    await writer.write(clientHello(sni));

    const certs = [];
    let hsBuf = new Uint8Array(0);
    let recBuf = new Uint8Array(0);   // bytes not yet forming a complete record
    while (true) {
      let rec;
      try { rec = await reader.read(); } catch (e) { throw new Error("tls read failed: " + (e && e.message || e)); }
      if (rec.done) throw new Error("connection closed before certificate");
      let stream = recBuf.length ? concat(recBuf, new Uint8Array(rec.value)) : new Uint8Array(rec.value);
      let off = 0;
      while (true) {
        if (stream.length - off < 5) break;          // header split across chunks
        const type = stream[off];
        const len = (stream[off + 3] << 8) | stream[off + 4];
        if (off + 5 + len > stream.length) break;    // body split across chunks
        if (type === 21) throw new Error("tls alert " + ((stream[off + 5] << 8) | stream[off + 6]));
        if (type === 22) hsBuf = concat(hsBuf, stream.subarray(off + 5, off + 5 + len));
        off += 5 + len;
      }
      recBuf = stream.subarray(off);
      // Walk complete handshake messages inside hsBuf.
      let pos = 0;
      while (pos + 4 <= hsBuf.length) {
        const mlen = (hsBuf[pos + 1] << 16) | (hsBuf[pos + 2] << 8) | hsBuf[pos + 3];
        if (pos + 4 + mlen > hsBuf.length) break;      // message split across records
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
  const listLen = (body[0] << 16) | (body[1] << 8) | body[2];
  const end = Math.min(3 + listLen, body.length);
  const out = [];
  let p = 3;
  while (p + 3 <= end) {
    const clen = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
    p += 3;
    if (clen === 0 || p + clen > end) throw new Error("malformed certificate entry");
    out.push(Buffer.from(body.subarray(p, p + clen)));
    p += clen;
  }
  return out;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a); out.set(b, a.length);
  return out;
}

// Minimal TLS 1.2 ClientHello: SNI, eight ECDHE AES-GCM suites, three curves,
// eight signature algos. Fixed sizes; server_name carries one hostname.
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
    ext(0x000d, pack([u16(sigalgs.length)]), sigalgs),
  ]);
  const exts = pack([u16(extBytes.length)], extBytes);

  const cipherLenU16 = u16(suites.length);
  const hello = pack([
    u16(0x0303),                                   // client_version = TLS 1.2
    crypto.getRandomValues(new Uint8Array(32)),    // random
    [0],                                           // session_id: none
    cipherLenU16, suites,
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

function sum(bodies) { return bodies.reduce((n, b) => n + b.length, 0); }

function u16(n) { return [n >> 8, n & 0xff]; }
function u24(n) { return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]; }

// pack: arrays / numbers (bytes) and Uint8Arrays, flattened left to right.
function pack(...items) {
  const out = new Uint8Array(count(...items));
  let i = 0;
  const write = (...chunks) => {
    for (const c of chunks) {
      if (c instanceof Uint8Array) { out.set(c, i); i += c.length; }
      else if (Array.isArray(c)) write(...c);
      else out[i++] = c & 0xff;
    }
  };
  write(...items);
  return out;
}

function count(...items) {
  let n = 0;
  for (const c of items) {
    if (c instanceof Uint8Array) n += c.length;
    else if (Array.isArray(c)) n += count(...c);
    else n++;
  }
  return n;
}

function ascii(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0x7f;
  return out;
}
