// Shared input-safety helpers for bot commands.
//
// Two layers of fetch protection (SSRF guard RESTORED — removal reverted):
//   1. SSRF — fetchUrlSafe() pins DNS, rejects non-public IPs at every hop
//      (including redirects), and caps response size, so anyone using the bot
//      cannot make it request internal hosts (169.254.169.254, localhost,
//      LAN) and read the response back in the reply. (Operator note: still
//      run this bot on an isolated host/network; defense in depth.)
//   2. IP-LOGGER hosts are refused as well (see IPLOGGER_KEYWORDS): fetching
//      one would hand the operator's/host's IP to a grabber service.
//   Per-request hardening kept in both layers: http(s) only, no credentials
//   in the URL, redirect cap (5), no https->http downgrade, timeout + byte
//   caps, gzip-bomb-safe decoding.
// PATH TRAVERSAL protection is unchanged: sanitizeFilename() reduces any
// attachment name to a safe basename.
//
// Attachment downloads (downloadFile in each command) are NOT reworked here:
// their host is always Discord's CDN. Only the user-supplied `url` string
// option flows through the fetchers above.
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const zlib = require('zlib');

// A real Roblox client sends Accept-Encoding: gzip, deflate, so we do too —
// but then we MUST decode the response, and we must decode it WITHOUT
// materialising the whole thing first.
//
// The previous decodeBody() called gunzipSync() and only compared the length
// afterwards, so a 30 KB gzip bomb already committed 30 MB of heap before the
// cap was consulted (measured: 30,604 bytes -> 31,457,280 bytes). At the 5 MB
// request cap a ~1000:1 ratio is gigabytes per request. Streaming with a hard
// output ceiling stops it at the ceiling.
function decompressorFor(encoding) {
  const enc = String(encoding || '').toLowerCase();
  try {
    if (enc.includes('gzip')) return zlib.createGunzip();
    if (enc.includes('br')) return zlib.createBrotliDecompress();
    if (enc.includes('deflate')) {
      // Servers vary between raw deflate and zlib-wrapped. Try zlib first; if
      // the stream errors, the caller falls back to inflateRaw.
      return zlib.createInflate();
    }
  } catch { /* unsupported */ }
  return null;
}

// Decode with a hard ceiling on the OUTPUT. Returns { body } or
// { error: 'exceeded the N byte limit after decoding' }. Never buffers more than
// maxOutput, so a bomb is abandoned the moment it crosses the line.
function decodeBodyCapped(raw, encoding, maxOutput) {
  const z = decompressorFor(encoding);
  if (!z) return { body: raw };
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      // Destroy so the decompressor stops burning CPU on the rest.
      try { z.destroy(); } catch { /* already gone */ }
      fn(arg);
    };
    z.on('data', (c) => {
      total += c.length;
      if (total > maxOutput) {
        finish(resolve, { error: `Response exceeds ${maxOutput} byte limit after decoding` });
        return;
      }
      chunks.push(c);
    });
    z.on('error', () => finish(resolve, { body: raw }));
    z.on('end', () => finish(resolve, { body: Buffer.concat(chunks) }));
    z.end(raw);
  });
}

// Some servers mislabel raw deflate as deflate. Retry once with inflateRaw
// before giving up and using the bytes as-is.
async function decodeBodyCappedWithFallback(raw, encoding, maxOutput) {
  const enc = String(encoding || '').toLowerCase();
  let out = await decodeBodyCapped(raw, encoding, maxOutput);
  if (out.error) return out;
  if (!enc.includes('deflate') || out.body === raw) return out;
  const alt = await new Promise((resolve) => {
    const z = zlib.createInflateRaw();
    const chunks = [];
    let total = 0;
    let settled = false;
    const finish = (v) => { if (settled) return; settled = true; try { z.destroy(); } catch { /* */ } resolve(v); };
    z.on('data', (c) => {
      total += c.length;
      if (total > maxOutput) { finish({ error: `Response exceeds ${maxOutput} byte limit after decoding` }); return; }
      chunks.push(c);
    });
    z.on('error', () => finish({ body: raw }));
    z.on('end', () => finish({ body: Buffer.concat(chunks) }));
    z.end(raw);
  });
  // Only prefer the raw-deflate result when it actually differs.
  return (alt && !alt.error && alt.body !== raw) ? alt : out;
}

function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

function inCidr(ip, cidr, bits) {
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(cidr);
  if (a === null || b === null) return false;
  const mask = bits === 0 ? 0 : (~0 >>> (32 - bits)) << (32 - bits);
  return (a & mask) === (b & mask);
}

// Expand any textual IPv6 form (including embedded IPv4 and "::" zero
// compression) into 8 numeric 16-bit groups. String-prefix matching cannot do
// this: the same address has many spellings, which is how the previous check
// let `0:0:0:0:0:ffff:127.0.0.1` and `::127.0.0.1` through.
function parseIpv6(ip) {
  let s = String(ip || '').toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);      // drop a zone id
  if (!s.includes(':')) return null;

  // A trailing dotted-quad (::ffff:127.0.0.1) becomes two hex groups.
  let tail = [];
  const lastColon = s.lastIndexOf(':');
  const trailing = s.slice(lastColon + 1);
  if (trailing.includes('.')) {
    const v4 = ipv4ToInt(trailing);
    if (v4 === null) return null;
    tail = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    // Splice the hex groups in directly. Building a '0:0' placeholder and then
    // regex-replacing it consumed the separating colon, yielding '::ffff808:808'
    // and a parse failure for every embedded-dotted-quad address.
    s = s.slice(0, lastColon + 1) + tail.map((n) => n.toString(16)).join(':');
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  // Inside each half every colon must separate two groups. Filtering empty
  // strings instead would accept malformed spellings such as 2001:db8:::1.
  const strictGroups = (part) => {
    if (!part) return [];
    if (part.startsWith(':') || part.endsWith(':') || part.includes('::')) return null;
    const groups = [];
    for (const g of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      groups.push(parseInt(g, 16));
    }
    return groups;
  };
  const head = strictGroups(halves[0]);
  const rear = halves.length === 2 ? strictGroups(halves[1]) : [];
  if (!head || !rear) return null;
  // NB: head/rear already hold parsed numbers here. An earlier revision
  // re-ran the hex regex over those NUMBERS (coerced to decimal strings)
  // and re-appended parseInt(x, 16) reinterpretations: any group whose
  // decimal value exceeded 4 chars (e.g. 0x50c0 = "20672") nulled the whole
  // parse (blocking legit public IPv6 like GitHub Pages'), and every
  // surviving parse carried corrupted trailing groups.
  // Just assemble head + zero-fill + rear.
  const groups = [...head];
  const fill = 8 - groups.length - rear.length;
  if (halves.length === 2) {
    if (fill < 0) return null;
    for (let i = 0; i < fill; i++) groups.push(0);
  } else if (groups.length !== 8) {
    return null;
  }
  for (const g of rear) groups.push(g);
  return groups.length === 8 ? groups : null;
}

// The low 32 bits of an IPv6 address, as dotted quad. Used for the forms that
// embed an IPv4 address: v4-mapped (::ffff:0:0/96), v4-compatible (::/96),
// 6to4 (2002::/16) and NAT64 (64:ff9b::/96).
function embeddedIpv4(g) {
  return `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
}

function ipv4IsBlocked(ip) {
  return inCidr(ip, '127.0.0.0', 8) || inCidr(ip, '10.0.0.0', 8) ||
    inCidr(ip, '172.16.0.0', 12) || inCidr(ip, '192.168.0.0', 16) ||
    inCidr(ip, '169.254.0.0', 16) || inCidr(ip, '0.0.0.0', 8) ||
    inCidr(ip, '224.0.0.0', 4) || inCidr(ip, '240.0.0.0', 4) ||
    inCidr(ip, '100.64.0.0', 10) || inCidr(ip, '192.0.2.0', 24) ||
    inCidr(ip, '198.51.100.0', 24) || inCidr(ip, '203.0.113.0', 24) ||
    inCidr(ip, '192.88.99.0', 24);
}

// True if the IP is NOT globally routable (and therefore must never be
// fetched server-side). Covers loopback, private, link-local (cloud metadata
// 169.254.169.254 lives here), multicast, CGNAT, docs, reserved, and every
// IPv6 form that can carry or reach a private IPv4 destination.
function isBlockedIp(ip) {
  const raw = String(ip == null ? '' : ip);
  // Anything with a colon is an IPv6 candidate. net.isIP() REJECTS the
  // embedded-dotted-quad form (::ffff:8.8.8.8 returns 0), so gating on it would
  // push a legitimate public address into the "not an IP" branch and block it.
  if (raw.includes(':')) {
    const g = parseIpv6(raw);
    if (!g) return true;                       // unparseable -> refuse
    const isZeroPrefix = g.slice(0, 5).every((x) => x === 0);
    // ::1 loopback, :: unspecified
    if (isZeroPrefix && g[5] === 0 && (g[6] !== 0 || g[7] <= 1)) return true;
    // ::ffff:0:0/96 IPv4-mapped and ::/96 IPv4-compatible -> judge the IPv4.
    if (isZeroPrefix && (g[5] === 0xffff || g[5] === 0)) {
      return ipv4IsBlocked(embeddedIpv4(g));
    }
    // 2002::/16 6to4 — the IPv4 lives in groups 1-2.
    if (g[0] === 0x2002) {
      return ipv4IsBlocked(`${g[1] >> 8}.${g[1] & 255}.${g[2] >> 8}.${g[2] & 255}`);
    }
    // 64:ff9b::/96 NAT64 (and its 64:ff9b:1::/48 local-use variant).
    if (g[0] === 0x0064 && g[1] === 0xff9b) {
      return ipv4IsBlocked(embeddedIpv4(g));
    }
    // fe80::/10 link-local, fec0::/10 deprecated site-local, fc00::/7 ULA,
    // ff00::/8 multicast.
    if ((g[0] & 0xffc0) === 0xfe80) return true;
    if ((g[0] & 0xffc0) === 0xfec0) return true;
    if ((g[0] & 0xfe00) === 0xfc00) return true;
    if ((g[0] & 0xff00) === 0xff00) return true;
    // 100::/64 discard-only, 2001:db8::/32 documentation, 2001:2::/48
    // benchmarking, 2001:10::/28 ORCHID, 2001::/32 Teredo, 3ffe::/16 6bone.
    if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true;
    if (g[0] === 0x2001 && g[1] === 0x0db8) return true;
    if (g[0] === 0x2001 && g[1] === 0x0002) return true;
    if (g[0] === 0x2001 && (g[1] & 0xfff0) === 0x0010) return true;
    if (g[0] === 0x2001 && g[1] === 0x0000) return true;
    if (g[0] === 0x3ffe) return true;
    return false;
  }
  if (net.isIP(raw) !== 4) return true; // not an IP at all -> block
  return ipv4IsBlocked(raw);
}

// Resolve + validate. All returned addresses must be public; any blocked
// address rejects the whole hostname (kills DNS-rebinding-by-round-robin).
// Returns a validated IP string to pin the subsequent fetch to.
async function resolvePinned(hostname) {
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch (err) {
    throw new Error(`DNS lookup failed for ${hostname}`);
  }
  if (!addresses || addresses.length === 0) throw new Error(`No DNS records for ${hostname}`);
  for (const a of addresses) {
    if (isBlockedIp(a.address)) {
      throw new Error(`Blocked host (resolves to non-public IP): ${hostname}`);
    }
  }
  return addresses[0].address;
}

// ---- IP-logger blocklist -----------------------------------------------
// Hosts whose SOLE purpose is logging visitor IPs (grabber links). Fetching
// one would hand the operator's/host's IP to the grabber, so every fetch
// entry point refuses them on every hop (initial URL + each redirect).
// Substring match on the normalized hostname, so mirrors and subdomains
// (x.iplogger.com) are caught too.
const IPLOGGER_KEYWORDS = [
  'iplogger', // iplogger.com / .org / .ru (+ mirrors)
  'grabify',  // grabify.link / grabify.org (+ mirrors)
  'yip.su',   // Yippy
  'blasze',   // blasze.tk
  'iplis.ru',
  '02ip',     // 02ip.ru (+ mirrors)
  'ipgrab',
];

function isIpLoggerHost(host) {
  const h = String(host || '').trim().toLowerCase()
    .replace(/^\[+/, '').replace(/\]+$/, '').replace(/\.+$/, '');
  if (!h) return false;
  return IPLOGGER_KEYWORDS.some((k) => h.includes(k));
}

function assertNotIpLogger(host) {
  if (isIpLoggerHost(host)) {
    throw new Error(`Blocked IP-logger URL host: ${host}`);
  }
}

function requestOnce({ scheme, ip, port, host, path: reqPath, servername, timeoutMs, maxBytes, headers: extraHeaders }) {
  return new Promise((resolve, reject) => {
    const lib = scheme === 'https:' ? https : http;
    // Caller headers are additive only. Host is pinned to the validated
    // request target afterwards, so a caller cannot redirect virtual-host
    // routing while the connection remains pinned to a validated IP.
    const headers = sanitizeRequestHeaders(extraHeaders);
    if (!headers['User-Agent']) headers['User-Agent'] = 'Nita-Bot/3.0';
    headers.Host = host;
    const req = lib.get({
      hostname: ip,
      port,
      path: reqPath,
      headers,
      servername, // SNI for https so cert validation uses the real hostname
      timeout: timeoutMs,
    }, (res) => {
      // Redirects are followed by the caller after re-validation, never here.
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        resolve({ redirect: res.headers.location });
        return;
      }
      if (res.statusCode !== 200) {
        // The provider's own message is usually the whole answer ("Invalid
        // session", "expired", "key required"). Draining straight to the
        // socket threw that away and left a bare "HTTP 400", so read a short
        // prefix of the error body and fold it into the message.
        const errChunks = [];
        let errBytes = 0;
        res.on('data', (c) => {
          if (errBytes >= 512) return;
          errBytes += c.length;
          errChunks.push(c);
        });
        res.on('end', () => {
          let detail = Buffer.concat(errChunks).toString('utf-8');
          // Flatten an HTML error page down to something readable.
          detail = detail.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
          if (detail.length > 160) detail = `${detail.slice(0, 160)}…`;
          reject(new Error(`Download failed: HTTP ${res.statusCode}${detail ? ` — ${detail}` : ''}`));
        });
        res.on('error', () => reject(new Error(`Download failed: HTTP ${res.statusCode}`)));
        return;
      }
      const chunks = [];
      let bytes = 0;
      let over = false;
      res.on('data', (c) => {
        bytes += c.length;
        // Cap on the wire (compressed) AND after decoding, so a zip bomb
        // cannot slip under the limit by compressing well.
        if (bytes > maxBytes) {
          over = true;
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on('end', async () => {
        if (over) {
          reject(new Error(`Response exceeds ${maxBytes} byte limit`));
          return;
        }
        try {
          const raw = Buffer.concat(chunks);
          const decoded = await decodeBodyCappedWithFallback(raw, res.headers['content-encoding'], maxBytes);
          if (decoded.error) {
            reject(new Error(decoded.error));
            return;
          }
          resolve({ body: decoded.body.toString('utf-8') });
        } catch (err) {
          reject(new Error(`Could not decode ${res.headers['content-encoding'] || 'plain'} response: ${err.message}`));
        }
      });
      res.on('error', reject);
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Fetch timed out')); });
    req.on('error', reject);
  });
}

function defaultPort(protocol) {
  return protocol === 'https:' ? '443' : '80';
}

// Header names and values accepted from callers. Node rejects malformed
// headers, but sanitize before the request is constructed so one bad custom
// header cannot alter routing-critical headers or abort an otherwise valid
// fetch. Routing headers are always supplied by the caller of the sanitizer.
const FORBIDDEN_REQUEST_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'expect',
  'trailer',
  'te',
  'upgrade',
]);
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER_VALUE_RE = /^[ \t\x21-\x7E]*$/;

function sanitizeRequestHeaders(extraHeaders) {
  const out = {};
  if (!extraHeaders || typeof extraHeaders !== 'object') return out;
  for (const [rawName, rawValue] of Object.entries(extraHeaders)) {
    const name = String(rawName || '');
    if (!HEADER_NAME_RE.test(name)) continue;
    if (FORBIDDEN_REQUEST_HEADERS.has(name.toLowerCase())) continue;
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    const clean = [];
    for (const value of values) {
      const text = String(value == null ? '' : value);
      if (text && HEADER_VALUE_RE.test(text)) clean.push(text);
    }
    if (clean.length > 0) out[name] = clean.length === 1 ? clean[0] : clean.join(', ');
  }
  return out;
}

// Host allowlists may be supplied as an array or comma-separated string. They
// are matched case-insensitively after removing IPv6 brackets and a trailing
// DNS dot, so equivalent spellings cannot evade the list.
function normalizeAllowHosts(allowHosts) {
  const source = allowHosts == null
    ? []
    : (Array.isArray(allowHosts) ? allowHosts : String(allowHosts).split(','));
  const out = new Set();
  for (const entry of source) {
    let host = String(entry || '').trim().toLowerCase();
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    host = host.replace(/\.+$/, '');
    if (host) out.add(host);
  }
  return out.size > 0 ? out : null;
}

function normalizedAllowHost(host) {
  let value = String(host || '').trim().toLowerCase();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  return value.replace(/\.+$/, '');
}

function isHttpsDowngrade(fromUrl, toUrl) {
  return !!fromUrl
    && !!toUrl
    && fromUrl.protocol === 'https:'
    && toUrl.protocol === 'http:'
    && process.env.ALLOW_HTTP_DOWNGRADE !== '1';
}

// Hostname from a URL without the IPv6 brackets the WHATWG parser keeps, so
// net.isIP() and DNS both see a bare address. u.hostname for http://[::1]/ is
// "[::1]", which net.isIP() rejects (0), so the address used to be sent to DNS
// instead of being range-checked.
function bareHost(u) {
  const h = u.hostname;
  return (h.startsWith('[') && h.endsWith(']')) ? h.slice(1, -1) : h;
}

// Host header value: bare hostname, plus the port when it is not the default
// (some CDNs and virtual hosts route on it).
function hostHeader(u) {
  const h = bareHost(u);
  const d = defaultPort(u.protocol);
  return u.port && String(u.port) !== d ? `${h}:${u.port}` : h;
}

// Fetch a user-supplied URL with DNS pinning, public-IP enforcement (every
// redirect hop re-validated), IP-logger refusal, and a size cap. Returns the
// body as text unless `response: 'buffer'` is requested. Optional `headers`
// overrides/adds request headers (e.g. a Roblox UA so Luarmor/Junkie loader
// URLs answer the bot the way they'd answer a client). Optional `allowHosts`
// restricts every hop to named hosts, and `maxRedirects` bounds redirects
// (0 disables following them).
async function fetchUrlSafe(rawUrl, { timeoutMs = 30000, maxBytes = 10 * 1024 * 1024, headers, allowHosts = null, maxRedirects = 3, response = 'text' } = {}) {
  const allowed = normalizeAllowHosts(allowHosts);
  const maxHops = Number.isInteger(maxRedirects) ? Math.min(Math.max(maxRedirects, 0), 5) : 3;
  const wantBuffer = response === 'buffer';
  const toBody = (decodedBody) => {
    if (wantBuffer) {
      return Buffer.isBuffer(decodedBody) ? decodedBody : Buffer.from(String(decodedBody == null ? '' : decodedBody), 'utf-8');
    }
    return Buffer.isBuffer(decodedBody) ? decodedBody.toString('utf-8') : String(decodedBody == null ? '' : decodedBody);
  };
  let current = rawUrl;
  for (let hop = 0; ; hop++) {
    if (hop > maxHops) throw new Error('Too many redirects');
    let u;
    try {
      u = new URL(current);
    } catch {
      throw new Error('Invalid URL');
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new Error('Only http(s) URLs are allowed');
    }
    if (u.username || u.password) throw new Error('URLs with credentials are not allowed');
    const host = bareHost(u);
    if (!host) throw new Error('Invalid URL');
    if (allowed && !allowed.has(normalizedAllowHost(host))) {
      throw new Error(`Host not allowed for this request: ${host}`);
    }
    assertNotIpLogger(host);
    const ip = net.isIP(host) ? host : await resolvePinned(host);
    if (isBlockedIp(ip)) throw new Error(`Blocked host: ${host}`);
    const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
    const result = await requestOnce({
      scheme: u.protocol, ip, port, host: hostHeader(u),
      path: (u.pathname || '/') + (u.search || ''),
      servername: u.protocol === 'https:' ? host : undefined,
      timeoutMs, maxBytes, headers,
    });
    if (result.redirect) {
      // Resolve relative redirects against the current URL, then re-validate.
      const next = new URL(result.redirect, u);
      // Refuse a plaintext downgrade. Without this an attacker who can answer
      // the first hop can bounce us to http:// and read/modify the rest of the
      // chain in clear text. Opt out only if a provider genuinely requires it.
      if (isHttpsDowngrade(u, next)) {
        throw new Error(`Refusing to follow a redirect from https to http (${next.host})`);
      }
      current = next.toString();
      continue;
    }
    return toBody(result.body);
  }
}

// Discord attachment downloader. Attachments already arrive through Discord's
// CDN, but the fetcher itself must not become a general-purpose downloader:
// the host allowlist, zero redirects, timeout, and byte cap are enforced here.
const ATTACHMENT_HOSTS = Object.freeze(['cdn.discordapp.com', 'media.discordapp.net']);

async function fetchAttachmentSafe(rawUrl, { timeoutMs = 20000, maxBytes = 10 * 1024 * 1024, allowHosts = ATTACHMENT_HOSTS, maxRedirects = 0, headers } = {}) {
  return fetchUrlSafe(rawUrl, {
    timeoutMs,
    maxBytes,
    headers: { 'User-Agent': 'Nita-Bot/3.0', ...(headers || {}) },
    allowHosts,
    maxRedirects,
    response: 'buffer',
  });
}

// POST with the same guarantees as fetchUrlSafe: DNS pinning, public-IP
// enforcement on every redirect hop, IP-logger refusal, a size cap, and an
// optional host allowlist. Used for provider APIs that need a body (e.g. the
// Jnkie delivery endpoint).
function postUrlSafe(rawUrl, { body = '', timeoutMs = 20000, maxBytes = 1024 * 1024, headers: extraHeaders, allowHosts = null, contentType = 'text/plain' } = {}) {
  const allowed = normalizeAllowHosts(allowHosts);
  const current0 = rawUrl;
  const hops = 2; // a POST that redirects is re-POSTed once, then gives up
  const run = (current, attempt) => new Promise((resolve, reject) => {
    let u;
    try { u = new URL(current); } catch { reject(new Error('Invalid URL')); return; }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      reject(new Error('Only http(s) URLs are allowed'));
      return;
    }
    if (u.username || u.password) reject(new Error('URLs with credentials are not allowed'));
    const host = bareHost(u);
    if (allowed && !allowed.has(normalizedAllowHost(host))) {
      reject(new Error(`Host not allowed for this request: ${host}`));
      return;
    }
    (async () => {
      assertNotIpLogger(host);
      const ip = net.isIP(host) ? host : await resolvePinned(host);
      if (isBlockedIp(ip)) throw new Error(`Blocked host: ${host}`);
      return { ip, u, host };
    })().then(({ ip, u, host }) => {
      const lib = u.protocol === 'https:' ? https : http;
      const payload = Buffer.from(String(body), 'utf-8');
      // Routing-critical headers are pinned after caller headers.
      const headers = {
        ...sanitizeRequestHeaders(extraHeaders),
        Host: hostHeader(u),
        'User-Agent': 'Nita-Bot/3.0',
        'Content-Type': contentType,
        'Content-Length': payload.length,
      };
      const req = lib.request({
        method: 'POST',
        hostname: ip,
        port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
        path: (u.pathname || '/') + (u.search || ''),
        headers,
        servername: u.protocol === 'https:' ? host : undefined,
        timeout: timeoutMs,
      }, (res) => {
        // Follow at most one redirect, re-validating the destination.
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && attempt < hops) {
          res.resume();
          let next;
          try { next = new URL(res.headers.location, u); } catch { reject(new Error('Invalid redirect target')); return; }
          // POST bodies deserve the same downgrade protection as GET.
          if (isHttpsDowngrade(u, next)) {
            reject(new Error(`Refusing to follow a redirect from https to http (${next.host})`));
            return;
          }
          // Re-POSTing the body to a DIFFERENT origin would hand the payload
          // (for .get2 that is the user's script key) to whatever host the
          // redirect names. Only same-origin redirects may keep the body;
          // otherwise stop rather than leak it.
          const sameOrigin = next.hostname === u.hostname
            && (next.port || defaultPort(next.protocol)) === (u.port || defaultPort(u.protocol));
          if (!sameOrigin) {
            reject(new Error(`Refusing to re-POST the request body across origins (${u.hostname} -> ${next.hostname})`));
            return;
          }
          resolve(run(next.toString(), attempt + 1));
          return;
        }
        const chunks = [];
        let bytes = 0;
        let over = false;
        res.on('data', (c) => {
          bytes += c.length;
          if (bytes > maxBytes) { over = true; req.destroy(); return; }
          chunks.push(c);
        });
        res.on('end', () => {
          if (over) { reject(new Error(`Response exceeds ${maxBytes} byte limit`)); return; }
          resolve({
            statusCode: res.statusCode,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
        res.on('error', reject);
      });
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.on('error', reject);
      req.write(payload);
      req.end();
    }).catch(reject);
  });
  return run(current0, 0);
}

// Reduce any user-supplied filename to a safe basename: no directories, no
// leading dots, no special chars, bounded length. Never returns empty.
function sanitizeFilename(name, fallback = 'file.luau') {
  let base = path.basename(String(name || ''));
  base = base.replace(/^\.+/, '');
  base = base.replace(/[^a-zA-Z0-9._-]/g, '_');
  if (!base || base === '.' || base === '..') return fallback;
  if (base.length > 100) {
    const ext = path.extname(base);
    base = base.slice(0, 100 - ext.length) + ext;
  }
  return base;
}

// ---- Secrets-exfil patch -----------------------------------------------
// Threat: a traced guest script runs `readfile("/.secrets.env")` (or any host
// path) and `print`s the result; the bot then relays that output to
// Discord, exfiltrating bot secrets. Layered defense:
//   1. The Lune sandbox itself has no host-fs access (in-memory VFS only),
//      so such reads already yield nil — but defense in depth demands the
//      bot NEVER emit secret material even if a layer above slips.
//   2. scrubSecrets() redacts secret material from ALL outbound text
//      (replies AND attached file bodies) before anything is sent.
// Never attach the original upload back; only analysis outputs.
//
// scrubSecrets works in four passes, because a naive "does the output contain
// the token" check is trivially bypassed by a guest that re-encodes it:
//   a. literal values pulled from the environment (exact match)
//   b. base64 / base64url / hex encodings of those same values
//   c. shape signatures for secrets we never held (tokens, PEM blocks, ...)
//   d. `KEY=value` / `"key": "value"` assignments in any position
const SECRET_NAME_RE = /TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|COOKIE|SESSION|AUTH|CLIENT_ID|PRIVATE/i;

// Cached: scrubSecrets runs on every embed field and every attachment body,
// and this used to re-walk all of process.env each time.
let _secretCache = null;
function secretValues() {
  if (_secretCache) return _secretCache;
  const vals = new Set();
  for (const [k, v] of Object.entries(process.env)) {
    if (!v || typeof v !== 'string') continue;
    // 8 chars minimum: below that an env value is almost always a common
    // word (PATH fragments, "true", locale) and redacting it corrupts output.
    if (SECRET_NAME_RE.test(k) && v.length >= 8) vals.add(v);
  }
  // Longest first so overlapping values redact fully.
  _secretCache = [...vals].sort((a, b) => b.length - a.length);
  return _secretCache;
}

// (Re)build the cache — call after mutating process.env in tests.
function resetSecretCache() { _secretCache = null; _encCache.clear(); }

// Encoded forms a guest could print instead of the raw secret.
function encodedForms(value) {
  const buf = Buffer.from(value, 'utf-8');
  const forms = [
    buf.toString('base64'),
    buf.toString('base64url'),
    buf.toString('hex'),
  ];
  // Standard base64 wraps at 76 columns in some encoders.
  if (forms[0].length > 76) {
    forms.push(forms[0].replace(/(.{76})/g, '$1\n'));
  }
  return forms;
}

const _encCache = new Map();
function encodedFormsCached(value) {
  let f = _encCache.get(value);
  if (!f) { f = encodedForms(value); _encCache.set(value, f); }
  return f;
}

// Shapes for secrets the process may never have held: a guest that dumped
// some other credential, or a partly-read .env.
const SHAPE_PATTERNS = [
  // Discord bot token: 24.6.27 base64url segments.
  { re: /(?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}(?![A-Za-z0-9_-])/g, label: 'discord-token' },
  // AWS access key id.
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, label: 'aws-key-id' },
  // Common provider tokens.
  { re: /\b(?:sk|rk|pk)-(?:live|test|prod)-[A-Za-z0-9_-]{16,}\b/g, label: 'provider-token' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, label: 'github-token' },
  { re: /\b(?:xox[abpsr]|glpat)-[A-Za-z0-9-]{10,}\b/g, label: 'chat-token' },
  // JSON Web Token.
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, label: 'jwt' },
  // PEM private key block (header + body + footer).
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, label: 'private-key' },
];

// KEY=value / "key": "value" anywhere in the text (not just at line start),
// tolerating quotes around the name and the value.
//
// A name is secret-bearing when one of its underscore/dot/camel segments is a
// sensitive word: SCRIPT_KEY, apiKey, auth_token, sessionKey, ...
// Segment-based matching is deliberate — a \b-keyword regex cannot reach a
// compound name, because \b does not exist between "_" and "KEY", which is
// exactly why SCRIPT_KEY = "…" used to survive into published output.
const SENSITIVE_WORD = /^(?:key|keys|apikey|token|secret|password|passwd|pwd|credential|credentials|auth|authorization|session|private|clientsecret|accesskey|scriptkey|apptoken|bearer|jwt|cookie|signature|salt|hmac|dsn)$/i;

function isSecretAssignmentName(raw) {
  const name = String(raw || '');
  if (!name || name.length > 80) return false;
  const segments = name.split(/[._\-]+/).filter(Boolean);
  if (!segments.length) return false;
  // camelCase: apiKey -> api + Key.
  const expanded = segments.flatMap((seg) => seg.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/\s+/));
  return expanded.some((seg) => SENSITIVE_WORD.test(seg));
}

// dotenv-style names are SHOUTY (API_KEY, SCRIPT_KEY). A lowercase `key`
// usually binds an identifier in code rather than holding a secret.
function isDotenvName(raw) {
  const n = String(raw || '');
  return n.length > 0 && n === n.toUpperCase() && /[A-Z]/.test(n);
}

// One assignment: NAME <op> VALUE. The VALUE shape decides how strict to be —
// a quoted literal is configuration, a bare identifier is code.
const ASSIGN_RE = /(^|[\s,{;)(.])((?:"|')?)([A-Za-z0-9_.\-]+)((?:"|')?)(\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;}{)\n]+)/g;

function scrubSecrets(text) {
  let out = String(text == null ? '' : text);
  if (out.length === 0) return out;

  // (a) literal env values, (b) their encodings. The encoded forms are cached:
  // scrubSecrets runs on every embed field and every attachment body, so
  // re-encoding each secret each time was pure repeated work.
  for (const v of secretValues()) {
    if (out.includes(v)) out = out.split(v).join('[REDACTED]');
    for (const enc of encodedFormsCached(v)) {
      if (enc.length >= 12 && out.includes(enc)) out = out.split(enc).join('[REDACTED]');
    }
  }

  // (c) shape signatures.
  for (const { re } of SHAPE_PATTERNS) {
    out = out.replace(re, '[REDACTED]');
  }

  // Credentials embedded in a URL: keep the host, drop only user:pass.
  out = out.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/:@]+:[^\s/@]+@/gi, '$1[REDACTED]@');

  // (d) assignments. Keep the name, drop the value.
  out = out.replace(ASSIGN_RE, (m, ctx, q1, name, q2, op, value) => {
    if (!isSecretAssignmentName(name)) return m;
    const quoted = (value.startsWith('"') || value.startsWith("'"));
    // Quoted literal -> configuration, redact. Bare identifier -> most likely
    // code (`local key = KEYBOARD`), so only redact when the name is dotenv-style.
    if (!quoted && !isDotenvName(name)) return m;
    return `${ctx}${q1}${name}${q2}${op}"[REDACTED]"`;
  });
  // `Bearer <token>` is a credential even though it is not an assignment.
  out = out.replace(/\bBearer\s+(?:"[^"\n]{6,}|'[^'\n]{6,}'|[A-Za-z0-9._~+/=-]{12,})/g, 'Bearer [REDACTED]');

  return out;
}

// ---- Guest file-access reporting ----------------------------------------
// A traced script that reaches for host paths is worth telling the user
// about, even when the sandbox denies it: it is the clearest signal that an
// upload is hostile. Returns [{ fn, path }] for every file access we can see,
// in three forms:
//   1. literal `readfile("...")` style calls in recovered source
//   2. `-- [vfs] <path> (N bytes)`  — writes that landed in the in-memory jail
//   3. `-- [static:*] <path>`        — harvested strings, i.e. intent, which
//      is what we get when execution was denied and no call was recorded
const FILE_FN_RE = /\b(readfile|writefile|appendfile|deletefile|loadfile|dofile|isfile|isfolder|makefolder|listfiles)\s*\(\s*(["'])([^"'\n]*)\2/g;
const VFS_WRITE_RE = /^\s*--\s*\[vfs\]\s*(\S+)(?:\s+\(\d+\s*bytes?\))?\s*$/i;
const STATIC_STR_RE = /^\s*--\s*\[static:[^\]]*\]\s*(\S.*?)\s*$/i;

// Paths that mean the guest is reaching outside its own sandbox.
const SENSITIVE_PATH_RE =
  /(^|\/)(\.env(\.[\w.-]+)?|\.git|\.ssh|\.aws|\.config|id_rsa|id_ed25519|authorized_keys|known_hosts|\.npmrc|\.netrc|passwd|shadow|\.secrets\.env|discord-bot)(\/|$|\.)/i;

function isSensitivePath(p) {
  const s = String(p || '');
  return SENSITIVE_PATH_RE.test(s) || s.includes('..');
}

function scanFileAccess(text) {
  const src = String(text == null ? '' : text);
  const seen = new Set();
  const out = [];
  const push = (fn, p) => {
    if (!p) return;
    const key = `${fn}:${p}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ fn, path: p });
  };

  // 1. literal calls
  FILE_FN_RE.lastIndex = 0;
  let m;
  while ((m = FILE_FN_RE.exec(src)) !== null) push(m[1], m[3]);

  // 2 + 3. tracer dump markers
  for (const line of src.split('\n')) {
    const w = VFS_WRITE_RE.exec(line);
    if (w) { push('writefile', w[1]); continue; }
    const s = STATIC_STR_RE.exec(line);
    // Only harvested strings that look like a path we care about; otherwise
    // every captured string ("start", "print") would be reported.
    if (s && isSensitivePath(s[1])) push('accessed', s[1]);
  }
  return out;
}

function suspiciousFileAccess(attempts) {
  return (attempts || []).filter((a) => isSensitivePath(a.path));
}

module.exports = {
  fetchUrlSafe,
  fetchAttachmentSafe,
  ATTACHMENT_HOSTS,
  normalizeAllowHosts,
  sanitizeRequestHeaders,
  isHttpsDowngrade,
  postUrlSafe,
  sanitizeFilename,
  isBlockedIp,
  isIpLoggerHost,
  IPLOGGER_KEYWORDS,
  scrubSecrets,
  secretValues,
  resetSecretCache,
  parseIpv6,
  embeddedIpv4,
  decodeBodyCapped,
  bareHost,
  hostHeader,
  scanFileAccess,
  suspiciousFileAccess,
  SHAPE_PATTERNS,
  isSecretAssignmentName,
};
