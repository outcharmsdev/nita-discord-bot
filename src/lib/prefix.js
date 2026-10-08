// Prefix commands for the Nita bot.
//   .help -> list commands
//   .l  [attachment | url | ```code```]  -> Nita V1.1 (lune run ../nita_v11.lua)
//   .l2 [attachment | url | ```code```]  -> v1 + nitav2 replay + JSONL events
//   .deobfuscate [attachment | url | ```code```] [obfuscator] -> LeakD API (auto-detect + route)
//   .detect [attachment | url | ```code```] -> LeakD /detect (obfuscator name + confidence)
//   .get <url> [key]      -> fetch any loader URL(s), unpack LOCALLY, follow stages
//   .luarmor <url> [key]  -> fetch Luarmor URL(s), unpack LOCALLY, follow stages
//   .jnkie <url> [key]    -> fetch Junkie URL(s), unpack LOCALLY, follow stages
//   .luarmorfetch <url> [key] -> Luarmor v4 bootstrap chain, LOCALLY (tools/Luarmor-Fetch)
//   .luarmorprobe [attachment | url | code] -> static Luarmor client analysis, LOCALLY
//   .flowauth <loader-url> -> FlowAuth v3 chain -> recovered payload, LOCALLY
//   .luast [attachment | url | ```code```] -> LUAST v1 + L3 recovery, LOCALLY
//   .lphv15 [attachment | url | ```code```] [--trace] -> Luraph v15 devirt, LOCALLY (alias .luraphv15)
//   .luraph [attachment | url | ```code```] -> LeakD /luraphv15 API (alias .luraphapi)
//   .luraphv14 [attachment | url | ```code```] [14.7|14.8|14.9] -> Luraph v14.x devirt, LOCALLY
//   .ironbrew1 [attachment | url | ```code```] [--trace] -> Ironbrew1 devirt, LOCALLY
//   .keyforgefetch <loader-url> [--xbox|--mac|--studio|--mobile] -> fetch + identify loader payload
//
// Locked to ALLOWED_CHANNEL_IDS (comma-separated; default 1540908077178552421).
// Only these channels may use bot commands. Everything the bot sends
// (replies AND attached file bodies) passes through scrubSecrets()
// so traced `print`s can never exfiltrate bot secrets back to Discord.
const { AttachmentBuilder } = require('discord.js');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { sanitizeFilename, scrubSecrets, fetchUrlSafe, fetchAttachmentSafe, postUrlSafe, scanFileAccess, suspiciousFileAccess } = require('./safety');
const { COLORS, codePreview, makeEmbed, replyEmbed, editEmbed, editEmbedWithFiles } = require('./embed');

const ALLOWED_CHANNEL_IDS = String(process.env.ALLOWED_CHANNEL_IDS || process.env.ALLOWED_CHANNEL_ID || '1540908077178552421')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
// Legacy single-ID export (first entry) for anything still importing it.
const ALLOWED_CHANNEL_ID = ALLOWED_CHANNEL_IDS[0];
const WATERMARK = '--[[Monke]]';
const LUNE_BIN = process.env.LUNE_BIN || 'lune';
// This bot lives in <workspace>/discord-bot, tracers in <workspace>/.
const NITA_V1 = process.env.NITA_V1_PATH
  || path.join(__dirname, '..', '..', '..', 'nita_v11.lua');
const NITA_V2 = process.env.NITA_V2_PATH
  || path.join(__dirname, '..', '..', '..', 'nitav2.lua');
const TEMP_DIR = path.join(__dirname, '..', '..', 'temp');
// Own local unpacker (Luau, runs under Lune — no external API, no network).
const LUARMOR_DRIVER = process.env.LUARMOR_PATH
  || path.join(__dirname, '..', '..', '..', 'luarmor.lua');
// LeakD deobfuscation API — used by .deobfuscate / .detect / .luraph.
// Docs: https://leakd.vercel.app/api — base: https://leakd.up.railway.app
// Auth: `X-Api-Key` header (mandatory, 401 without it). Key lives ONLY in
// .env as LEAKD_API_KEY (UPLOAD_API_TOKEN accepted as deprecated fallback)
// and is never logged — scrubSecrets() redacts it from all bot output.
function leakdBaseUrl() {
  return (process.env.LEAKD_API_BASE_URL || 'https://leakd.up.railway.app').replace(/\/+$/, '');
}

function leakdApiKey() {
  return process.env.LEAKD_API_KEY || process.env.UPLOAD_API_TOKEN || '';
}

// Parse the optional `.deobfuscate` obfuscator hint: first word after the
// command once code blocks, URLs, and key forms are stripped.
// Returns { hint, endpoint } — endpoint is null when no hint was given;
// hint is non-null with a null endpoint when the word matches nothing.
function parseDeobfuscateHint(content) {
  const afterCmd = String(content || '').split(/\s+/).slice(1).join(' ');
  const haystack = afterCmd
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/https?:\/\/[^\s<>"'`]+/gi, ' ')
    .replace(/\bkey\s*=\s*[^\s<>"'`]+/gi, ' ')
    .replace(/--key\s+[^\s<>"'`]+/gi, ' ')
    .replace(/(?:^|\s)-k\s+[^\s<>"'`]+/gi, ' ');
  const hint = haystack.split(/\s+/)
    .map((t) => t.trim().replace(/^<+/, '').replace(/>+$/, '').replace(/[).,\];!]+$/, ''))
    .find((t) => t && !/^(--key|-k|key=)$/i.test(t)) || '';
  return { hint, endpoint: hint ? mapDetectorToEndpoint(hint) : null };
}
// Detector name -> LeakD endpoint. Detector labels come from /detect
// `top_result.name`; matching is case-insensitive substring so minor label
// drift ("MoonSec V3", "moonsecv3", "Luraph v15", ...) still routes.
const LEAKD_ENDPOINTS = {
  moonsec: '/moonsec',
  prometheus: '/prometheus',
  ironbrew: '/ironbrew2',
  ironveil: '/ironveil',
  hercules: '/hercules',
  goofyscator: '/goofyscator',
  clyde: '/clydedeobf',
  '77fuscator': '/77fuscator',
  psu: '/psu',
  xhider: '/xhider',
  luaobfuscator: '/luaobfuscator',
  moonveil: '/moonveil',
  luraph: '/luraphv15',
};

function mapDetectorToEndpoint(name) {
  // Normalize so user picks like `/psu`, `Moon-Sec V3`, `luraph v15`,
  // `clydedeobf` all still match.
  const n = String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!n) return null;
  // Short aliases / alternate spellings users actually type.
  const ALIAS = {
    moonsecv3: 'moonsec', ms3: 'moonsec', ms: 'moonsec',
    prometheus: 'prometheus', prom: 'prometheus',
    ironbrew2: 'ironbrew', ib2: 'ironbrew', ib: 'ironbrew',
    ironveil: 'ironveil', iv: 'ironveil',
    hercules: 'hercules', herc: 'hercules',
    goofyscator: 'goofyscator', goofy: 'goofyscator',
    clydedeobf: 'clyde', clydeprotection: 'clyde',
    '77fuscator': '77fuscator', '77f': '77fuscator',
    xhider: 'xhider',
    luaobfuscator: 'luaobfuscator', luaobf: 'luaobfuscator',
    moonveil: 'moonveil', moonveil2: 'moonveil', mv: 'moonveil',
    luraphv15: 'luraph', luraph15: 'luraph', luraph: 'luraph',
  };
  if (ALIAS[n]) return LEAKD_ENDPOINTS[ALIAS[n]];
  if (n.includes('moonveil')) return LEAKD_ENDPOINTS.moonveil;
  if (n.includes('moonsec')) return LEAKD_ENDPOINTS.moonsec;
  if (n.includes('prometheus')) return LEAKD_ENDPOINTS.prometheus;
  if (n.includes('ironbrew')) return LEAKD_ENDPOINTS.ironbrew;
  if (n.includes('ironveil')) return LEAKD_ENDPOINTS.ironveil;
  if (n.includes('hercules')) return LEAKD_ENDPOINTS.hercules;
  if (n.includes('goofyscator')) return LEAKD_ENDPOINTS.goofyscator;
  if (n.includes('clyde')) return LEAKD_ENDPOINTS.clyde;
  if (n.includes('77fuscator') || n.includes('77fuscat')) return LEAKD_ENDPOINTS['77fuscator'];
  if (n.includes('psu')) return LEAKD_ENDPOINTS.psu;
  if (n.includes('xhider')) return LEAKD_ENDPOINTS.xhider;
  if (n.includes('luaobfuscator')) return LEAKD_ENDPOINTS.luaobfuscator;
  if (n.includes('luraph')) return LEAKD_ENDPOINTS.luraph;
  return null;
}

function supportedEndpointList() {
  return Object.entries(LEAKD_ENDPOINTS).map(([k, v]) => `${k} (\`${v}\`)`).join(', ');
}

// Human-friendly picker shown when auto-detect fails or the user asks for
// `.deobfuscate list`: one line per choice with the exact command to run.
function deobfuscatorChoiceList() {
  const LABEL = {
    moonsec: 'MoonSec V3', prometheus: 'Prometheus', ironbrew: 'Ironbrew2',
    ironveil: 'Ironveil', hercules: 'Hercules', goofyscator: 'Goofyscator',
    clyde: 'Clyde Protection', '77fuscator': '77fuscator', psu: 'PSU',
    xhider: 'XHider', luaobfuscator: 'LuaObfuscator', moonveil: 'Moonveil 2.x (beta)',
    luraph: 'Luraph v15',
  };
  return Object.keys(LEAKD_ENDPOINTS)
    .map((k) => `• **${LABEL[k] || k}** — \`.deobfuscate ${k}\` + attach file / URL / code block`)
    .join('\n');
}

// POST multipart `file` to a LeakD endpoint. Returns the raw JSON body.
// Throws scrubbed errors for missing key / 401 / 429 / success:false.
async function leakdPostFile(endpointPath, sourceCode, sourceName) {
  const apiKey = leakdApiKey();
  if (!apiKey) throw new Error('LeakD API not configured — set `LEAKD_API_KEY` in `.env` (get a key at https://discord.gg/AwGHNh7Z7T).');
  const code = String(sourceCode == null ? '' : sourceCode);
  if (!code) throw new Error('No code to send — source was empty.');
  const form = new FormData();
  form.append('file', new Blob([code], { type: 'text/plain' }), sanitizeFilename(sourceName || 'script.lua', 'script.lua'));
  const url = leakdBaseUrl() + endpointPath;
  let response;
  try {
    response = await axios.post(url, form, {
      headers: { 'X-Api-Key': apiKey },
      timeout: 90000,
      maxBodyLength: 10 * 1024 * 1024,
    });
  } catch (err) {
    if (err.response) {
      const status = err.response.status;
      const raw = err.response.data;
      const detail = typeof raw === 'string' ? raw
        : (raw && raw.error ? String(raw.error) : JSON.stringify(raw));
      if (status === 401) throw new Error('LeakD rejected the API key (401) — check `LEAKD_API_KEY` in `.env`.');
      if (status === 429) throw new Error('LeakD rate limit hit (429, ~120/min) — wait a minute and retry.');
      throw new Error(`LeakD API error HTTP ${status}: ${scrubSecrets(detail).substring(0, 300)}`);
    }
    if (err.code === 'ECONNABORTED') throw new Error('LeakD API timed out (90s limit).');
    throw new Error(`LeakD API failed: ${scrubSecrets(err.message).substring(0, 300)}`);
  }
  const d = response.data;
  if (d && typeof d === 'object' && d.success === false) {
    throw new Error(`LeakD: ${scrubSecrets(String(d.error || 'request failed')).substring(0, 300)}`);
  }
  return d;
}

// Call POST /detect. Resolves { name, confidence, raw }.
async function leakdDetect(sourceCode, sourceName) {
  const d = await leakdPostFile('/detect', sourceCode, sourceName);
  const top = (d && typeof d === 'object' && d.top_result) || {};
  const name = top.name || d.name || d.obfuscator || null;
  const confidence = top.confidence != null ? top.confidence : (d.confidence != null ? d.confidence : null);
  if (!name) throw new Error('LeakD detector returned no obfuscator name.');
  return { name: String(name), confidence, raw: d };
}

// Pull the deobfuscated/beautified source out of the various LeakD
// success envelopes (key differs per endpoint).
function leakdResultCode(d) {
  if (d == null) return null;
  if (typeof d === 'string') return d;
  if (typeof d === 'object') {
    for (const k of ['deobfuscated_code', 'beautified_code', 'code', 'obfuscated_code', 'result', 'output', 'source', 'deobfuscated']) {
      if (typeof d[k] === 'string' && d[k].length > 0) return d[k];
    }
  }
  return null;
}

// ---- Output watermark ------------------------------------------------------
// Upstream deobfuscators stamp their own banner into the result, sometimes
// spelled with Cyrillic homoglyphs ("DеоbfuѕсаtеԜіth LeaκD") so a plain
// "Deobfuscated by" regex never matches. Match on the invite URL instead —
// it is plain ASCII — drop that whole leading comment block, strip any
// remaining invite links, and prepend our own banner.
const WATERMARK_NAME = process.env.WATERMARK_NAME || 'EpicLogger';
// Cyrillic/Greek characters that render identically to ASCII. Watermark text
// is deliberately spelled with these so that a literal "LeakD" match fails:
// "Sоurсe Соԁе Dеоbfuѕсatеd Ву LeаκD". Folding a line back to ASCII lets us
// recognise it; the output text itself is never modified this way.
const HOMOGLYPHS = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0455': 's', '\u04BB': 'h',
  '\u0458': 'j', '\u04CF': 'l', '\u0501': 'd', '\u051B': 'q', '\u051D': 'w',
  '\u026F': 'l', '\u03BA': 'k', '\u03B1': 'a', '\u03B5': 'e', '\u03BF': 'o',
  '\u03C1': 'p', '\u03C5': 'u', '\u03C7': 'x', '\u0458': 'j',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M',
  '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
  '\u0423': 'Y', '\u0425': 'X', '\u0405': 'S', '\u0406': 'I', '\u0408': 'J',
};
const FOLD_RE = new RegExp(`[${Object.keys(HOMOGLYPHS).join('')}]`, 'g');

function foldHomoglyphs(s) {
  return String(s == null ? '' : s).replace(FOLD_RE, (c) => HOMOGLYPHS[c] || c);
}

// Vendors whose banners we replace with our own.
const VENDOR_WATERMARK_RE = /\b(?:leakd|deobfuscator\s+luraph|moonsec|prometheus)\b/i;
// A comment that is a watermark once folded: "---@source Source Code
// Deobfuscated By LeakD", "-- DеоbfuѕсаtеԜіth LeaκD", etc.
function isWatermarkLine(line) {
  if (!isComment(line)) return false;
  const folded = foldHomoglyphs(line);
  if (INVITE_RE.test(folded)) return true;
  return VENDOR_WATERMARK_RE.test(folded);
}

// Read `--flag VALUE` from message text as an integer, clamped to a sane range.
function valFlag(content, flag) {
  const esc = flag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = String(content || '').match(new RegExp(`(?:^|\\s)${esc}\\s+(\\d+)`, 'i'));
  return m ? Number(m[1]) : null;
}

function clampInt(v, dflt, min, max) {
  // null/undefined/'' must fall back to the default. Number(null) is 0 and
  // Number('') is 0, both "finite" — without this guard a missing --depth
  // silently became 0 and killed stage-following entirely.
  if (v === null || v === undefined || v === '') return dflt;
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function isComment(line) {
  return /^\s*--/.test(line);
}

const INVITE_RE = /(?:discord(?:app)?\.com\/invite|discord\.gg|dsc\.gg)\/[A-Za-z0-9]+/gi;

// Chunky informal banners some upstreams prepend to trace output ("yeah this
// ran at runtime and its gonna be shit"). Cosmetic, not code, and not ours.
const INFORMAL_BANNER_RE = /its gonna be|its gonna|\bosrry\b|not gonna be full|yeah this ran at runtime/i;

// The deobfuscation engines prepend a credit header of their own to every result
// (obfuscators/base.py `credit_header`), which is two comment lines: the "Why do
// i love gpt ..." line and a dsc.gg invite. The invite half is caught by
// INVITE_RE below; this catches the rest so no third-party tagline survives.
// Matched loosely on the distinctive phrase rather than pinned to one engine's
// exact wording. Patching the vendored engine instead would be undone by the
// next `git pull`, and `bin/obfuscators/base.py` is a second copy of it anyway.
// Deliberately narrow: the header's other note ("Local names are inferred from
// use") is useful to whoever reads the output, so it stays.
const ENGINE_CREDIT_RE = /why do i love gpt/i;

function stripInviteLinks(code) {
  return String(code)
    .split('\n')
    // Any comment line whose whole purpose was a third-party watermark or an
    // invite goes entirely; keep real code lines and just excise the link.
    .filter((l) => !(isComment(l) && (isWatermarkLine(l) || INFORMAL_BANNER_RE.test(l) || ENGINE_CREDIT_RE.test(l))))
    .join('\n')
    .replace(INVITE_RE, '')
    // A comment left holding nothing but a bare scheme is a dead invite
    // remnant ("-- https://"); drop it rather than ship the husk.
    .replace(/^[ \t]*--[ \t]*(?:https?:\/\/?[ \t]*)?$/gm, '')
    .replace(/[ \t]+$/gm, '');
}

// Drop the leading run of comment lines when it carries an invite link (i.e.
// it is a watermark banner rather than genuine script header). A real header
// like Luarmor's "-- Do not save this file" has no invite, so it survives.
// Drop leading decoration-only comment lines (the `-----` rules around a
// banner). Real headers such as Luarmor's "-- Do not save this file" are
// never decoration-only, so they survive. Watermark and invite lines are
// already gone by this point (stripInviteLinks removes them anywhere).
function stripBanner(code) {
  const lines = code.split('\n');
  let start = 0;
  const isDecoration = (l) => /^\s*--[-\s=*~_.]*$/.test(l);
  while (start < lines.length && (isDecoration(lines[start]) || lines[start].trim() === '')) start++;
  return lines.slice(start).join('\n');
}

// Canonical header for every result this bot hands over: our watermark, no
// third-party branding, no invite links.
function applyWatermark(code) {
  // Strip watermark/invite lines FIRST: a banner is usually decoration line,
  // watermark, invite, decoration. Trimming decoration before the watermark is
  // gone would stop at the watermark and leave the trailing rule behind.
  // Idempotent: drop any banner we already added. Without this, re-watermarking
  // a body that was watermarked before scaffolding removal stacked two headers.
  // `m` is required: without it ^ and $ only anchor at the string ends, so the
  // existing header never matched and watermarks stacked up.
  // The rule lines are `-- ----`, i.e. a Lua comment marker THEN the rule, so
  // the pattern has to allow that `--` prefix.
  const RULES = /^[ \t]*--[ \t]*-{3,}[ \t]*$\n[ \t]*--[ \t]*Deobfuscated By [^\n]*$\n[ \t]*--[ \t]*-{3,}[ \t]*$\n*/m;
  let clean = String(code == null ? '' : code).replace(RULES, '');
  clean = stripBanner(stripInviteLinks(clean)).replace(/^\n+/, '');
  return `-- ----------------------------------------------------\n-- Deobfuscated By ${WATERMARK_NAME}\n-- ----------------------------------------------------\n\n${clean}`;
}

const MAX_SOURCE_BYTES = 5 * 1024 * 1024;
const MAX_ATTACH_BYTES = 8 * 1024 * 1024;
// Local execution duration limit: 195s for tracer (.l/.l2) and unpacker
// runs. Big VM payloads need the headroom; the OS kill is the hard guard
// (Lune has no instruction hook), results still stream as partials.
const RUN_TIMEOUT_MS = 195000;

function isAllowedChannel(channelId) {
  return ALLOWED_CHANNEL_IDS.includes(String(channelId));
}

// ---- Pastefy upload (watermarked, zero comments) ----------------------------
// Uploads ONLY code: the reconstruction slice (`local _G ... return _G`)
// with every comment stripped by a string-aware lexer, plus the watermark.
// Findings/metadata stay in the Discord reply + attached files — the paste
// itself carries no `--` comments at all.
function stripLuaComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    // short/long strings: copy verbatim (respect backslash escapes)
    if (c === '"' || c === "'") {
      const q = c;
      out += c;
      i++;
      while (i < n) {
        out += src[i];
        if (src[i] === '\\') {
          if (i + 1 < n) out += src[i + 1];
          i += 2;
          continue;
        }
        if (src[i] === q) { i++; break; }
        i++;
      }
      continue;
    }
    // long-bracket strings [[..]], [==[..]==]: copy verbatim
    if (c === '[') {
      const m = src.slice(i).match(/^\[(=*)\[/);
      if (m) {
        const close = ']' + m[1] + ']';
        const end = src.indexOf(close, i + m[0].length);
        if (end === -1) { out += src.slice(i); break; }
        out += src.slice(i, end + close.length);
        i = end + close.length;
        continue;
      }
      out += c;
      i++;
      continue;
    }
    // comments (code region only — strings handled above)
    if (c === '-' && src[i + 1] === '-') {
      const m = src.slice(i + 2).match(/^\[(=*)\[/);
      if (m) {
        const close = ']' + m[1] + ']';
        const end = src.indexOf(close, i + 2 + m[0].length);
        i = end === -1 ? n : end + close.length;
      } else {
        const nl = src.indexOf('\n', i);
        i = nl === -1 ? n : nl; // drop comment, keep the newline
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// Build the Pastefy payload: watermark + the FULL result encoded as Lua
// CODE (a `_RESULT` table), then the comment-free reconstruction.
// Zero `--` comments anywhere in the paste: every finding (verdict,
// timeline, unknown reads, traps, net, remotes, strings, prints) becomes
// data, not comments. Falls back to reconstruction-only if parsing fails.
function luaQuote(s) {
  // Single-line ASCII-safe quoting: C0 controls + DEL become decimal
  // escapes (valid in all Lua/Luau). Bytes >= 0x80 pass through raw (UTF-8
  // stays readable); guest binary never arrives raw here anyway — the dump
  // already renders it as ASCII `\xNN` text via clean().
  return '"' + String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/[\x00-\x1f\x7f]/g, (c) => '\\' + String(c.charCodeAt(0)).padStart(3, '0'))
    + '"';
}

function luaScalar(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (/^-?\d+$/.test(s)) return s;
  if (/^-?\d+\.\d+$/.test(s)) return s;
  if (s === 'true' || s === 'false') return s;
  return luaQuote(s);
}

function parseDumpSections(recoveredText) {
  // Returns { verdict, header, sections, reconStart, reconEnd }.
  const lines = String(recoveredText).split('\n');
  let verdict = null;
  const header = {};
  const sections = {};
  let current = null;
  let reconStart = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    const t = l.trim();
    if (t === 'local _G = _G or {}') { reconStart = i; break; }
    let m = t.match(/^--\s*═{3,}\s*RESULT:\s*(.+?)\s*═{3,}\s*$/);
    if (m) { verdict = m[1]; continue; }
    m = t.match(/^--\s*───\s*(.+?)\s*───\s*$/);
    if (m) { current = m[1]; sections[current] = []; continue; }
    if (t.startsWith('--')) {
      const kv = t.slice(2).trim().match(/^([A-Za-z /-]+?):\s*(.+?)\s*$/);
      if (kv && current === null) {
        header[kv[1].trim()] = kv[2].trim();
      } else if (current !== null && t.length > 3) {
        sections[current].push(t.slice(2).trim());
      }
      continue;
    }
    current = null; // code line: not part of any section
  }
  return { verdict, header, sections, reconStart, lines };
}

function emitLuaTable(entries, indent) {
  // entries: array of [keyOrNull, renderedValue]
  const pad = '  '.repeat(indent);
  const inner = '  '.repeat(indent + 1);
  const parts = entries.map(([k, v]) => (k === null ? `${inner}${v}` : `${inner}[${luaQuote(k)}] = ${v}`));
  if (parts.length === 0) return '{}';
  return `{\n${parts.join(',\n')}\n${pad}}`;
}

function buildWatermarkedSource(recoveredText) {
  const text = String(recoveredText || '');
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.trim() === 'local _G = _G or {}');
  let end = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].trim() === 'return _G') { end = i; break; }
  }
  const parsed = parseDumpSections(text);
  const chunks = [WATERMARK, ''];
  // _RESULT table: the full findings as data.
  const rentries = [];
  if (parsed.verdict) rentries.push(['verdict', luaScalar(parsed.verdict)]);
  for (const [k, v] of Object.entries(parsed.header)) {
    rentries.push([k, luaScalar(v)]);
  }
  for (const [name, items] of Object.entries(parsed.sections)) {
    if (!Array.isArray(items) || items.length === 0) continue;
    const vals = items.slice(0, 200).map((it) => luaQuote(it));
    rentries.push([name, `{\n${vals.map((v) => '    ' + v).join(',\n')}\n  }`]);
  }
  if (rentries.length > 0) {
    chunks.push('local _RESULT = ' + emitLuaTable(rentries, 0));
    chunks.push('');
  }
  // Reconstruction slice, comments stripped (string-aware).
  if (start !== -1 && end !== -1 && end > start) {
    const slice = lines.slice(start, end + 1).join('\n');
    const stripped = stripLuaComments(slice)
      .split('\n')
      .map((l) => l.replace(/[ \t]+$/, ''))
      .filter((l, idx, arr) => !(l === '' && (idx === 0 || arr[idx - 1] === '')))
      .join('\n')
      .trim();
    if (stripped) chunks.push(stripped);
  }
  chunks.push('');
  const out = chunks.join('\n');
  if (!out.trim() || out.trim() === WATERMARK) return null;
  return out;
}

// True when the tracer's comment-free reconstruction holds no recovered
// code — just the `local _G = _G or {} ... return _G` boilerplate (the
// DORMANT case: Status ok, 0 globals). Delivering that as "the result" is
// a metadata-only husk, so callers switch to the findings-first path.
function isBoilerplateOnly(cleanText) {
  const lines = String(cleanText || '').split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && l !== 'local _G = _G or {}' && l !== 'return _G');
  return lines.length === 0;
}

// Best-effort dormant diagnosis from the tracer manifest: import gap
// (unknown global reads) + trap markers, e.g. "gated on: Loadstring;
// traps: TOSTRING_HIJACK". Returns '' when nothing is known.
function dormantWhy(manifestPath) {
  try {
    const raw = fs.readFileSync(manifestPath, 'utf-8');
    const m = JSON.parse(raw);
    const parts = [];
    const unknowns = Array.isArray(m.unknownReads) ? m.unknownReads.filter((u) => typeof u === 'string') : [];
    if (unknowns.length > 0) {
      parts.push(`gated on: ${unknowns.slice(0, 5).join(', ')}`);
    }
    const traps = Array.isArray(m.traps) ? m.traps.filter((t) => typeof t === 'string') : [];
    if (traps.length > 0) {
      parts.push(`traps: ${traps.slice(0, 5).join(', ')}`);
    }
    return parts.join('; ');
  } catch {
    return '';
  }
}

async function uploadFilebin(title, content, sessionDir) {
  // Fallback host when Pastefy is down: POST the raw bytes, the API answers
  // JSON with the bin id, and the file is served at /<id>/<filename>.
  // Example: curl --data-binary "@a.lua" -H "filename: a.lua" https://filebin.net/
  const endpoint = (process.env.FILEBIN_URL || 'https://filebin.net/').replace(/\/*$/, '/');
  const filename = String(title || 'recovered_clean.luau').replace(/[^\w.\-]+/g, '_').slice(0, 80) || 'file.luau';
  const tmpPath = path.join(sessionDir, 'filebin_upload.luau');
  fs.writeFileSync(tmpPath, String(content), 'utf-8');
  try {
    const body = await new Promise((resolve, reject) => {
      execFile('curl', ['-s', '-m', '30', '--data-binary', `@${tmpPath}`, '-H', `filename: ${filename}`, endpoint], {
        timeout: 35000,
        maxBuffer: 1024 * 1024,
      }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Filebin upload failed: ${err.message}`));
          return;
        }
        resolve(String(stdout || ''));
      });
    });
    let id = null;
    try {
      const data = JSON.parse(body);
      id = data && data.bin && data.bin.id;
    } catch {
      throw new Error(`Filebin returned an unexpected response: ${body.substring(0, 200)}`);
    }
    if (!id || !/^[A-Za-z0-9]+$/.test(String(id))) {
      throw new Error(`Filebin returned an unexpected response: ${body.substring(0, 200)}`);
    }
    return `https://filebin.net/${id}/${encodeURIComponent(filename)}`;
  } finally {
    try { fs.unlinkSync(tmpPath); } catch {}
  }
}

async function uploadPastefy(title, content, sessionDir) {
  // Anonymous upload, no API token: curl -F f=@file https://pastefy.app
  // Responds with the plain paste URL (e.g. https://pastefy.app/aDZPiREa).
  const base = (process.env.PASTEFY_URL || 'https://pastefy.app').replace(/\/+$/, '');
  const tmpPath = path.join(sessionDir, 'pastefy_upload.luau');
  fs.writeFileSync(tmpPath, String(content), 'utf-8');
  try {
    const url = await new Promise((resolve, reject) => {
      execFile('curl', ['-s', '-m', '30', '-F', `f=@${tmpPath};filename=${title || 'recovered_clean.luau'}`, base], {
        timeout: 35000,
        maxBuffer: 1024 * 1024,
      }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Pastefy upload failed: ${err.message}`));
          return;
        }
        const out = String(stdout || '').trim().split(/\s+/)[0] || '';
        if (!/^https?:\/\/[^\s]+$/.test(out)) {
          reject(new Error(`Pastefy returned an unexpected response: ${out.substring(0, 200)}`));
          return;
        }
        resolve(out);
      });
    });
    return url;
  } finally {
    try { fs.unlinkSync(tmpPath); } catch {}
  }
}

// (Text replies were replaced by embeds — see lib/embed.js. clampText
// there is the scrubbed length guard now.)

async function downloadCapped(url, dest, maxBytes = MAX_SOURCE_BYTES) {
  // Attachments are restricted to Discord's CDN with no redirects. Using the
  // hardened fetcher preserves every SSRF protection and avoids a second,
  // unpinned HTTP implementation.
  const data = await fetchAttachmentSafe(url, { timeoutMs: 20000, maxBytes });
  fs.writeFileSync(dest, data);
}

// ---- Static next-stage discovery (fetch-only mode) ------------------------
// `.get` never executes anything, so it cannot use the unpacker's stage
// extraction. Instead harvest candidate URLs from the source text: literals,
// long-bracket strings, and simple concatenations. Cheap, no sandbox.
// Is this URL plausibly a *script* endpoint? A bare site root, an HTML page,
// or an API JSON endpoint is not a next stage: fetching it just burns the
// escalation budget and reports a misleading failure.
//
// Extracted from harvestStageUrls so every stage-discovery path applies the
// same bar. It was previously bypassed by the loadstring pass, which is how
// `https://0x6auth.lol` (a 28KB HTML page) ended up queued as a stage.
function scriptLikeUrl(rawUrl) {
  const u = String(rawUrl || '').trim();
  if (u.length < 12 || u.length > 2000) return false;
  if (!/^https?:\/\/[^/]+\.[^/]+/.test(u)) return false;
  // Non-script asset references.
  if (/\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|mp[34]|pdf|zip|html?|php)(\?|$)/i.test(u)) return false;
  if (/^(?:https?:\/\/)?(?:www\.)?(?:github\.com|discord\.gg|discord\.com|twitter\.com|x\.com|youtu\.be|lura\.ph\/)/i.test(u)) return false;
  let pathname = '';
  try { pathname = new URL(u).pathname; } catch { return false; }
  // Site root: never a script.
  if (pathname === '' || pathname === '/') return false;
  if (/\.(html?|php|json|xml|map)$/i.test(pathname)) return false;
  return /\.(lua|luau|luac|txt)(\?|$)/i.test(pathname)
    || /\/(?:loader|loaders|script|scripts|file|files|payload|payloads|blob|blobs|raw|cdn|stage|stages|chunk|chunks|src|dist)\//i.test(pathname)
    // `/api/...` is only script-like with a script-shaped leaf. `/api/challenge`
    // and similar endpoints answer JSON, so require a code-ish extension or an
    // explicit payload word in the final segment.
    || (/\/api\//i.test(pathname) && (/\.(lua|luau|luac|txt)$/i.test(pathname) || /(?:payload|script|loader|stage|chunk|blob|raw)\b/i.test(pathname)));
}

function harvestStageUrls(body, { limit = 8, exclude = [] } = {}) {
  const src = String(body == null ? '' : body);
  if (!src) return [];
  const skip = new Set(exclude.map((u) => String(u)));
  const found = [];
  const seen = new Set();
  // http(s) URLs anywhere (covers quoted literals and concatenation pieces).
  const re = /https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+/g;
  let m;
  while ((m = re.exec(src)) !== null && found.length < limit * 4) {
    // Strip trailing punctuation that is almost never part of the URL.
    const u = m[0].replace(/[).,\];!:'"]+$/, '');
    if (skip.has(u) || seen.has(u)) continue;
    if (!scriptLikeUrl(u)) continue;
    seen.add(u);
    found.push(u);
  }
  return found.slice(0, limit);
}

// ---- Executor identification ----------------------------------------------
// Which client a script is written for. Signature-based over the source: the
// executor global it reaches for, or the name it asserts via identifyexecutor.
const EXECUTOR_SIGNATURES = [
  { name: 'Synapse X', re: /(?<![A-Za-z0-9_])syn\.(?:request|write|read|convert|list_callbacks|get_callbacks|security)/i },
  { name: 'Synapse X', re: /require\s*\(?\s*["']Synapse["']/i },
  { name: 'Fluxus', re: /(?<![A-Za-z0-9_])fluxus\./i },
  { name: 'Fluxus', re: /internal_name\s*==?\s*["']Fluxus["']/i },
  { name: 'KRNL', re: /(?<![A-Za-z0-9_])krnl\.|["']KRNL["']/i },
  { name: 'Solara', re: /(?<![A-Za-z0-9_])solara\.|identifyexecutor\s*\(\s*["']Solara["']/i },
  { name: 'Zygisk', re: /(?<![A-Za-z0-9_])zygisk\b/i },
  { name: 'PotX', re: /(?<![A-Za-z0-9_])PotX\b/i },
  { name: 'Arceus X', re: /(?<![A-Za-z0-9_])arceus\b/i },
  { name: 'Codex', re: /(?<![A-Za-z0-9_])codex\.[a-z_]+\(/i },
  { name: 'JitSync', re: /(?<![A-Za-z0-9_])jitsync\b/i },
  { name: 'Delta', re: /(?<![A-Za-z0-9_])delta\.(?:execute|resolve)/i },
  { name: 'Lime', re: /(?<![A-Za-z0-9_])lime[_.]?(?:getexecutorname|loaded)/i },
  { name: 'Wave', re: /(?<![A-Za-z0-9_])wave\.(?:execute|absin)/i },
  { name: 'AWP', re: /(?<![A-Za-z0-9_])awp\.(?:extract|library)/i },
];

// Executor-only globals. `getgenv` is the strongest single signal.
const EXECUTOR_GLOBALS = ['getgenv', 'getexecutorname', 'identifyexecutor', 'gethui', 'setclipboard', 'request', 'http_request', 'loadstring', 'setclipboard', 'queue_on_teleport', 'hookfunction', 'newproxy', 'getrawmetatable', 'setreadonly'];

function identifyExecutor(body) {
  const src = String(body == null ? '' : body);
  // Obfuscated bodies are huge; the head carries the client-detection block.
  const head = src.slice(0, 600000);
  const hits = [];
  const seen = new Set();
  for (const { name, re } of EXECUTOR_SIGNATURES) {
    if (seen.has(name)) continue;
    if (re.test(head)) { seen.add(name); hits.push(name); }
  }
  const globals = EXECUTOR_GLOBALS.filter((g) => new RegExp(`(?<![A-Za-z0-9_.])${g}(?![A-Za-z0-9_])`).test(head));
  let verdict = 'unknown / no executor globals detected';
  if (hits.length === 1) verdict = hits[0];
  else if (hits.length > 1) verdict = `${hits.slice(0, 3).join(', ')} (ambiguous — multiple client signatures)`;
  else if (globals.length) verdict = 'generic executor (no vendor-specific signature)';
  return { verdict, hits, globals };
}

// ---- Response sanity ------------------------------------------------------
// A 200 is not a script. Providers and CDNs answer with an HTML error page, a
// JSON envelope, or a binary blob often enough that calling those SUCCESS
// would be a lie. Classify before reporting.
// Human byte size for summaries ("764 KB", "1.5 MB").
function formatBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

function classifyBody(body) {
  const s = String(body == null ? '' : body);
  if (!s.length) return { ok: false, kind: 'empty', reason: 'empty body' };

  // Binary gate. Not all binary is junk: providers ship protected payloads as
  // opaque containers (a PolSec "PSC3Z" blob, a .NET assembly, compiled
  // bytecode) that the user's own loader decrypts at runtime. Those are a
  // successful FETCH of a protected asset, so report them as `container`
  // instead of discarding the bytes as a failure.
  const head = s.slice(0, 4000);
  const CONTAINERS = [
    { re: /^PSC[0-9]?Z/i, label: 'PolSec/PSC encrypted container' },
    { re: /^MZ/, label: 'PE/.NET assembly' },
    { re: /^\x1bLua/, label: 'compiled Lua bytecode' },
    { re: /^\x7fELF/, label: 'ELF binary' },
    { re: /^PK\x03\x04/, label: 'zip archive' },
    { re: /^\x1f\x8b/, label: 'gzip stream' },
  ];
  for (const c of CONTAINERS) {
    if (c.re.test(s.slice(0, 16))) {
      return { ok: true, kind: 'container', label: c.label, reason: `${c.label} (protected payload, not plain Lua)` };
    }
  }
  if (head.indexOf('\u0000') !== -1) return { ok: false, kind: 'binary', reason: 'binary data (contains NUL)' };
  let ctrl = 0;
  for (let i = 0; i < head.length; i++) {
    const c = head.charCodeAt(i);
    if (c < 9 || (c > 13 && c < 32) || c === 127) ctrl++;
  }
  if (head.length > 32 && ctrl / head.length > 0.02) {
    return { ok: false, kind: 'binary', reason: 'binary data (control-character density)' };
  }

  // Definite non-script containers, rejected before scoring.
  const trimmed = head.trimStart();
  if (/^<(!doctype|html|head|body|\?xml|svg)/i.test(trimmed)) {
    return { ok: false, kind: 'html', reason: 'HTML/XML document' };
  }
  if (/^[{[]/.test(trimmed)) {
    try {
      JSON.parse(s);
      return { ok: false, kind: 'json', reason: 'JSON document' };
    } catch { /* not JSON after all - fall through and score it */ }
  }

  // Positive detection: "not HTML/JSON/binary" is a denylist and always misses
  // the next format. Require evidence of real Lua/Luau syntax instead. Obfuscated
  // sources put everything on one line, so patterns span content rather than
  // lines.
  let score = 0;
  if (/\bfunction\b[\s\S]{0,400}?\bend\b/.test(s)) score += 4;
  else if (/\bfunction\b/.test(s)) score += 2;
  if (/\bif\b[\s\S]{0,200}?\bthen\b/.test(s)) score += 3;
  if (/\b(?:for|while)\b[\s\S]{0,120}?\bdo\b/.test(s)) score += 3;
  if (/\bfunction\b/.test(s)) score += 1;
  if (/(?:^|[^.\w])local\s+[A-Za-z_\[]/.test(s)) score += 1;
  if (/\breturn\b/.test(s)) score += 1;
  if (/(?:^|[^.\w])end\b/.test(s)) score += 1;
  if (/\bprint\s*\(/.test(s)) score += 1;
  if (/:GetService\s*\(/.test(s)) score += 2;
  if (/\b(?:loadstring|getgenv|getfenv|setfenv|pcall|select|table\.concat|string\.char|math\.random|task\.wait|gethui|identifyexecutor)\b/.test(s)) score += 2;
  if (/["'][^"'\n]{1,}["']/.test(s)) score += 1;
  if (/[A-Za-z_\]]\s*=\s*[^=]/.test(s)) score += 1;
  if (/::[A-Za-z_]|continue\b|export\s+type\b|task\.(?:wait|spawn|defer)\b/.test(s)) score += 1;

  // A markdown document can score high (it quotes real Lua in fenced blocks),
  // so reject prose containers explicitly before trusting the score.
  if (/^#{1,6}\s+\S/m.test(s.slice(0, 8000))) {
    return { ok: false, kind: 'markdown', reason: 'Markdown document, not a script' };
  }
  if ((s.match(/```/g) || []).length >= 2) {
    return { ok: false, kind: 'markdown', reason: 'fenced-code document, not a script' };
  }

  // 3 is the floor for honest small scripts ("local x = 1 print(x)" scores 3);
  // prose and CSS score 0, and HTML/JSON/binary never reach here.
  const MIN_SCORE = 3;
  if (score < MIN_SCORE) {
    return { ok: false, kind: 'not-lua', reason: `does not look like Lua/Luau (syntax score ${score}/${MIN_SCORE})` };
  }
  return { ok: true, kind: 'script', score };
}

// Transient conditions worth one more try: connection resets, timeouts, and
// 5xx/429 from an overloaded edge. A 404 or a blocked host will not change.
const TRANSIENT_RE = /(timed out|socket hang up|ECONNRESET|ECONNREFUSED|EAI_AGAIN|EPIPE|socket hangup|network|unreachable|HTTP (429|5\d\d))/i;

async function sleepMs(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Roblox desktop client profile. Several providers (Luarmor, FlowAuth, KeyForge
// and most executor-hosted loaders) answer differently depending on how
// "client-like" the request looks.
//
// IMPORTANT: these are WinInet headers, NOT Chromium ones. `Sec-CH-UA*` and
// `Sec-Fetch-*` are sent by browsers only — the Roblox client never sends them,
// so including them made us look like a browser. KeyForge answers a browser with
// a 345-byte "must be run from a Roblox executor" stub instead of the 613KB
// payload. Do not add client-hints or fetch-metadata headers here.
const ROBLOX_HEADERS = {
  'User-Agent': 'Roblox/WinInet',
  'Accept': '*/*',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate',
  'Cache-Control': 'no-cache',
  'Pragma': 'no-cache',
};

// Alternate client identities, selected by `--xbox` / `--mac` / `--studio` /
// `--mobile`. Only the User-Agent differs, as it does in the real clients.
const CLIENT_PROFILES = {
  win: { 'User-Agent': 'Roblox/WinInet' },
  xbox: { 'User-Agent': 'Roblox/Xbox' },
  mac: { 'User-Agent': 'Roblox/Mac' },
  studio: { 'User-Agent': 'RobloxStudio/0.680.0.0' },
  mobile: { 'User-Agent': 'Roblox/WinInet' },
};
const FLAVORS = {
  get2: {
    tag: 'get2', title: 'Fetched script (Jnkie-aware)',
    usage: '**Usage:** `.get2 <url> [key]`\nLike `.get`, plus it completes a **Jnkie delivery chain**: when the loader points at `api.jnkie.com/…/delivery/…`, it POSTs your key to get the CDN payload URL and fetches that.\n'
      + 'The key is only ever the one you type — never anything from the bot\'s environment.\n'
      + 'Flags: `--depth N` `--max N` `--budget N` `--no-detect` `--xbox|--mac|--studio|--mobile`\n',
    hint: null,
  },
  get: {
    tag: 'get', title: 'Fetched script',
    usage: '**Usage:** `.get <url> [key]`\nURL is **required** (up to 5 loader URLs), key is **optional**.\n'
      + 'Fetches the raw file(s) and follows the loader chain — no unpacking, no deobfuscation.\n'
      + 'Each URL is attempted up to 3 escalating times: **normal** → **deep** (alternate client identity) → **final** (every identity + a decode pass for protected payloads).\n'
      + 'Loaders that build their next URL at runtime (string.char / concat / VM) are followed by executing the loader in the sandbox, so `loadstring` stages are still found.\n'
      + 'Flags: `--depth N` chain depth (0-8, default 3) · `--max N` scripts (1-40, default 10) · `--budget N` seconds (20-900, default 150)\n'
      + 'Loadstring resolution: `--loadstring` run it on every stage · `--no-loadstring` disable it (default: only when static harvesting finds nothing)\n'
      + 'Client profile: `--xbox` `--mac` `--studio` `--mobile` · `--no-detect` skips obfuscator detection\n',
    hint: null,
  },
  luarmor: {
    tag: 'luarmor', title: 'Luarmor result (local)',
    usage: '**Usage:** `.luarmor <url> [key]`\nLuarmor URL is **required** (up to 5 URLs), key is **optional**.\n',
    hint: 'luarmor',
  },
  jnkie: {
    tag: 'jnkie', title: 'Junkie result (local)',
    usage: '**Usage:** `.jnkie <url> [key]`\nJunkie URL is **required** (up to 5 URLs), key is **optional**.\n',
    hint: 'jnkie',
  },
  flowauth: {
    tag: 'flowauth', title: 'FlowAuth result (local)',
    usage: '**Usage:** `.flowauth <url> [key]`\nFlowAuth URL is **required** (up to 5 URLs), key is **optional**.\n',
    hint: 'flowauth',
  },
  luast: {
    tag: 'luast', title: 'Luast result (local)',
    usage: '**Usage:** `.luast <url> [key]`\nLuast URL is **required** (up to 5 URLs), key is **optional**.\n',
    hint: 'luast',
  },
}

const PROVIDER_HINTS = {
  luarmor: ['luarmor', 'cdn.luarmor.net'],
  jnkie: ['jnkie', 'junkie'],
  flowauth: ['flowauth'],
  luast: ['luast'],
}

// Bare inline code after the command: `.lua print("test")`. Strips the
// command token and any flags, then treats the rest as Lua source. Requires a
// Lua-ish signal so `.lua hello there` does not obfuscate English prose.
// Opt-in per command via `{ inlineCode: true }` so other commands keep their
// existing input contract.
function extractInlineCode(content) {
  const noFences = String(content || '').replace(/```[\s\S]*?```/g, ' ');
  const urls = noFences.match(/https?:\/\/[^\s<>"'`]+/gi) || [];
  let text = noFences;
  for (const u of urls) text = text.split(u).join(' ');
  const parts = text.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return null;
  parts.shift(); // command token (`.lua`)
  const kept = [];
  for (let i = 0; i < parts.length; i++) {
    const t = parts[i];
    if (/^--level$/i.test(t)) { i++; continue; } // skip flag + value
    if (/^--level=/i.test(t)) continue;
    if (/^--(standard|high|paranoid|no-\S+)$/i.test(t)) continue;
    kept.push(t);
  }
  const code = kept.join(' ').trim();
  if (!code) return null;
  if (!/[()=;{}]|\b(?:print|local|function|return|for|while|if|then|end|game|script|task|loadstring)\b/i.test(code)) return null;
  return code;
}

async function collectSource(message, sessionDir, { inlineCode = false } = {}) {
  const allowedExts = ['.lua', '.luau', '.txt', '.luac'];
  const att = message.attachments.find((a) => {
    const ext = path.extname(a.name || '').toLowerCase();
    return allowedExts.includes(ext);
  }) || message.attachments.first();
  if (att) {
    const safeName = sanitizeFilename(att.name, 'script.luau');
    const inputPath = path.join(sessionDir, safeName);
    await downloadCapped(att.url, inputPath);
    return { inputPath, sourceName: safeName };
  }
  const urls = extractUrls(message.content);
  if (urls.length > 0) {
    const remoteUrl = urls[0];
    const safeName = sourceNameFromUrl(remoteUrl);
    const inputPath = path.join(sessionDir, safeName);
    // Executor-hosted loader URLs commonly gate on a client identity. Use the
    // same profile selection as `.get` so direct source loads do not receive
    // a browser-targeted guard page instead of the script.
    const profileName = clientProfileName(message.content);
    const body = await fetchUrlSafe(remoteUrl, {
      timeoutMs: 20000,
      maxBytes: MAX_SOURCE_BYTES,
      headers: clientProfileHeaders(profileName),
    });
    if (!body || body.length === 0) throw new Error('URL returned empty body');
    fs.writeFileSync(inputPath, body, 'utf-8');
    return { inputPath, sourceName: safeName };
  }
  const code = extractCodeBlock(message.content);
  if (code) {
    if (Buffer.byteLength(code, 'utf-8') > MAX_SOURCE_BYTES) {
      throw new Error('Code block exceeds size limit');
    }
    const inputPath = path.join(sessionDir, 'snippet.luau');
    fs.writeFileSync(inputPath, code, 'utf-8');
    return { inputPath, sourceName: 'snippet.luau' };
  }
  if (inlineCode) {
    const inline = extractInlineCode(message.content);
    if (inline) {
      if (Buffer.byteLength(inline, 'utf-8') > MAX_SOURCE_BYTES) {
        throw new Error('Inline code exceeds size limit');
      }
      const inputPath = path.join(sessionDir, 'inline.luau');
      fs.writeFileSync(inputPath, inline, 'utf-8');
      return { inputPath, sourceName: 'inline.luau' };
    }
  }
  return null;
}

async function publishPastefy(title, body, sessionDir) {
  if (process.env.PASTEFY_ENABLED === '0') return null;
  try {
    return await uploadPastefy(title, body, sessionDir);
  } catch (pasteErr) {
    // Pastefy down — try filebin.net before giving up. Disable with
    // FILEBIN_ENABLED=0. The filebin URL serves the content directly, so
    // callers must not append /raw to it (see pasteRawUrl).
    if (process.env.FILEBIN_ENABLED === '0') throw pasteErr;
    try {
      return await uploadFilebin(title, body, sessionDir);
    } catch (fbErr) {
      throw new Error(`${pasteErr.message} (filebin fallback also failed: ${fbErr.message})`);
    }
  }
}

// Raw-content URL for a published link: Pastefy needs /raw, filebin serves
// the file directly at its URL.
function pasteRawUrl(url) {
  const clean = String(url || '').replace(/\/+$/, '');
  try {
    if (new URL(clean).hostname === 'filebin.net') return clean;
  } catch { /* fall through to Pastefy form */ }
  return `${clean}/raw`;
}

function maybeAttach(files, filePath, name, skipped) {
  try {
    if (!fs.existsSync(filePath)) return false;
    const stat = fs.statSync(filePath);
    if (stat.size <= 0 || stat.size > MAX_ATTACH_BYTES) {
      if (Array.isArray(skipped)) skipped.push(`${name} (${formatBytes(stat.size)}, over Discord cap)`);
      return false;
    }
    const ext = path.extname(name).toLowerCase();
    if (['.lua', '.luau', '.txt', '.json', '.jsonl', '.log'].includes(ext)) {
      const body = scrubSecrets(fs.readFileSync(filePath, 'utf-8'));
      files.push(new AttachmentBuilder(Buffer.from(body, 'utf-8'), { name }));
    } else {
      files.push(new AttachmentBuilder(filePath).setName(name));
    }
    return true;
  } catch {
    return false;
  }
}

function summarizeDump(outPath) {
  const facts = {};
  try {
    const text = fs.readFileSync(outPath, 'utf-8');
    for (const line of text.split('\n').slice(0, 40)) {
      const m = line.match(/^--\s*([A-Za-z /-]+?):\s*(.+?)\s*$/);
      if (m) facts[m[1].trim()] = m[2].trim().slice(0, 120);
    }
  } catch { /* best-effort */ }
  return facts;
}

function safePathSegment(value, fallback = 'id') {
  // Discord IDs are numeric, but downstream cleanup deletes this directory.
  // Never allow separators, dots, or an empty name to reach path.join().
  const clean = String(value == null ? '' : value).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64);
  return clean || fallback;
}

function withSession(message, tag, fn) {
  if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });
  const tagSafe = safePathSegment(tag, 'session');
  const userSafe = safePathSegment(message && message.author ? message.author.id : null, 'user');
  const sessionDir = path.join(TEMP_DIR, `${tagSafe}_${Date.now()}_${userSafe}`);
  fs.mkdirSync(sessionDir, { recursive: true });
  // Evidence preservation: KEEP_TEMP=1 retains session dirs (inputs +
  // outputs) for forensics instead of auto-deleting them.
  const keep = process.env.KEEP_TEMP === '1';
  const cleanup = () => {
    if (keep) return;
    setTimeout(() => {
      try { fs.rmSync(sessionDir, { recursive: true, force: true }); } catch {}
    }, 5000);
  };
  return fn(sessionDir).finally(cleanup);
}

function runUnpacker(inputPath, outDir, key, staticOnly, timeoutMs, extraEnv) {
  return new Promise((resolve) => {
    fs.mkdirSync(outDir, { recursive: true });
    const args = ['run', LUARMOR_DRIVER, inputPath, outDir];
    if (key) args.push('--key', key);
    if (staticOnly) args.push('--static-only');
    execFile(LUNE_BIN, args, {
      timeout: timeoutMs || UNPACK_TIMEOUT_MS,
      maxBuffer: 10 * 1024 * 1024,
      // SIGTERM first lets Lune flush the partial replay it already wrote;
      // SIGKILL is the hard fallback the OS would send anyway.
      killSignal: 'SIGTERM',
      env: { ...process.env, ...sanitizeLuneEnv(extraEnv) },
    }, (err, stdout, stderr) => {
      resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

function luneTimeoutMs(env = process.env) {
  const raw = env ? (env.LUNE_TIMEOUT_MS ?? env.LUNE_RUN_TIMEOUT_MS ?? 120000) : 120000;
  const n = Number(raw);
  if (!Number.isFinite(n)) return 120000;
  return Math.min(Math.max(Math.round(n), 30000), 300000);
}

function sanitizeLuneEnv(extraEnv = {}) {
  // Only narrowly named tracer controls may pass through. Everything else in
  // process.env is inherited unchanged by the child.
  const out = {};
  if (!extraEnv || typeof extraEnv !== 'object') return out;
  for (const [key, value] of Object.entries(extraEnv)) {
    if (!/^NITA_[A-Z0-9_]+$/.test(key)) continue;
    if (value == null) continue;
    const text = String(value);
    if (text.length > 1000) continue;
    out[key] = text;
  }
  return out;
}

function isReadableFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function isInsideDir(parent, filePath) {
  const relative = path.relative(path.resolve(parent), path.resolve(filePath));
  return !!relative && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

// Missing this function used to make every `.l` and `.l2` invocation throw a
// ReferenceError. It launches Lune without a shell, bounds its runtime and
// output, and keeps all file arguments inside the bot's session directory.
function runLune(driver, inputPath, outputPath, extraEnv = {}) {
  return new Promise((resolve) => {
    const done = (err, stdout, stderr) => {
      resolve({
        err: err || null,
        stdout: String(stdout || ''),
        stderr: String(stderr || ''),
      });
    };
    try {
      if (typeof driver !== 'string' || !driver) throw new Error('Missing Lune driver path.');
      if (typeof inputPath !== 'string' || !inputPath) throw new Error('Missing Lune input path.');
      if (typeof outputPath !== 'string' || !outputPath) throw new Error('Missing Lune output path.');
      if (!isReadableFile(driver)) throw new Error(`Lune driver not found: ${driver}`);
      if (!isReadableFile(inputPath)) throw new Error(`Lune input not found: ${inputPath}`);
      if (!isInsideDir(TEMP_DIR, inputPath)) throw new Error('Lune input is outside the session directory.');
      if (!isInsideDir(TEMP_DIR, outputPath)) throw new Error('Lune output is outside the session directory.');
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      execFile(LUNE_BIN, ['run', driver, inputPath, outputPath], {
        timeout: luneTimeoutMs(),
        maxBuffer: 2 * 1024 * 1024,
        killSignal: 'SIGKILL',
        cwd: path.join(__dirname, '..', '..', '..'),
        env: { ...process.env, ...sanitizeLuneEnv(extraEnv) },
      }, (err, stdout, stderr) => done(err, stdout, stderr));
    } catch (err) {
      done(err, '', '');
    }
  });
}

function readStagesJson(outDir) {
  try {
    const raw = fs.readFileSync(path.join(outDir, 'stages.json'), 'utf-8');
    const d = JSON.parse(raw);
    return {
      stages: Array.isArray(d.stages) ? d.stages.filter((s) => s && typeof s.url === 'string') : [],
      kind: typeof d.kind === 'string' ? d.kind : 'unknown',
      needsKey: !!d.needsKey,
      layers: Number(d.layers) || 0,
      artifacts: Array.isArray(d.artifacts) ? d.artifacts.filter((a) => typeof a === 'string').slice(0, 10) : [],
    };
  } catch {
    return { stages: [], kind: 'unknown', needsKey: false, layers: 0, artifacts: [] };
  }
}

function buildLoaderSource(urls, key) {
  const urlLines = urls.map((u) => `        ${luaQuote(u)},`).join('\n');
  // NOTE: keep this template in sync with the canonical loader script:
  // CONFIG.urls + CONFIG.key feed Luarmor (`script_key`) and Junkie
  // (`SCRIPT_KEY`) loaders; requireKey=false keeps the key optional.
  return `local CONFIG = {
    urls = {
${urlLines}
    },
    key = ${luaQuote(key)},
    requireKey = false,
}

local req = (syn and syn.request) or (http and http.request) or http_request or request
local genv = (getgenv and getgenv()) or _G

local HEADERS = {
    ["User-Agent"] = "Roblox/WinInet",
    ["Accept"] = "*/*",
    ["Accept-Language"] = "en-US,en;q=0.9",
    ["Cache-Control"] = "no-cache",
}

local function kindOf(url)
    local u = url:lower()
    if u:find("luarmor", 1, true) then
        return "luarmor"
    end
    if u:find("jnkie", 1, true) or u:find("junkie", 1, true) then
        return "junkie"
    end
    return "script"
end

local function fetch(url)
    if req then
        local ok, res = pcall(req, { Url = url, Method = "GET", Headers = HEADERS })
        if ok and res and res.StatusCode == 200 and res.Body and #res.Body > 0 then
            return res.Body
        end
    end
    local ok, body = pcall(function()
        return game:HttpGet(url)
    end)
    if ok and body and #body > 0 then
        return body
    end
    return nil
end

local function setKey(kind, key)
    if kind == "luarmor" then
        script_key = key
    else
        script_key = key
        genv.SCRIPT_KEY = key
    end
end

local key = CONFIG.key
local hasKey = key and key ~= "" and not key:find("YOUR_", 1, true)

if CONFIG.requireKey and not hasKey then
    return warn("key required: set CONFIG.key")
end

if hasKey and not key:match("^[%w_%-]+$") then
    return warn("key has invalid characters")
end

for i, url in ipairs(CONFIG.urls) do
    local kind = kindOf(url)
    local label = kind .. "_" .. i

    if url:find("YOUR_", 1, true) then
        warn("[" .. label .. "] skipped: set the URL first")
    else
        if hasKey then
            setKey(kind, key)
        end

        local src = fetch(url)
        if not src then
            warn("[" .. label .. "] fetch failed")
        else
            local fn, cerr = loadstring(src)
            if not fn then
                warn("[" .. label .. "] compile failed:", cerr)
            else
                local ok, rerr = pcall(fn)
                if not ok then
                    warn("[" .. label .. "] run failed:", rerr)
                end
            end
        end
    end
end
`;
}

function extractUrls(text) {
  const raw = String(text || '').match(/https?:\/\/[^\s<>"'`]+/gi) || [];
  return raw.map((u) => {
    let s = u.replace(/^<+/, '').replace(/>+$/, '');
    // strip trailing punctuation that is never part of the URL
    s = s.replace(/[).,\];!]+$/, '');
    return s;
  }).filter((s) => /^https?:\/\/.+\..+/.test(s));
}

function sourceNameFromUrl(url) {
  try {
    const u = new URL(url);
    let base = path.basename(u.pathname || '');
    if (!base || base === '/' || !base.includes('.')) base = 'url_script.luau';
    return sanitizeFilename(base, 'url_script.luau');
  } catch {
    return 'url_script.luau';
  }
}

function readUnpackFacts(outDir) {
  // Reuse the `-- Key: value` lines for one-line summaries.
  const facts = {};
  try {
    const text = fs.readFileSync(path.join(outDir, 'unpack.log'), 'utf-8');
    for (const line of text.split('\n')) {
      const m = line.match(/^--\s*([A-Za-z /-]+?):\s*(.+?)\s*$/);
      if (m) facts[m[1].trim()] = m[2].trim().slice(0, 120);
    }
  } catch { /* best-effort */ }
  return facts;
}

function suggestNextCommand(name) {
  const n = String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!n) return null;
  if (n.includes('luarmor')) return '`.luarmor` / `.luarmorfetch` (local)';
  if (n.includes('flowauth')) return '`.flowauth` (local)';
  if (n.includes('luast')) return '`.luast` (local)';
  if (n.includes('luraph')) {
    return /14/.test(n) ? '`.luraphv14` (local)' : '`.luraph` (local)';
  }
  if (n.includes('ironbrew')) return '`.luraph` (local, handles ironbrew1)';
  const ep = mapDetectorToEndpoint(name);
  if (ep) return `\`.deobfuscate ${String(ep).replace(/^\//, '')}\``;
  return null;
}

function formatConfidence(c) {
  if (c == null) return '';
  let n = Number(c);
  if (!Number.isFinite(n) || n < 0) return '';
  if (n <= 1) n *= 100;
  if (n > 100) n = 100;
  return ` (${n.toFixed(0)}%)`;
}

async function cmdNita(message, v2) {
  const cmdName = v2 ? '.l2' : '.l';
  const sendErr = (text) => replyEmbed(message, {
    embeds: [makeEmbed({ title: `${cmdName} — error`, description: text, color: COLORS.error })],
  });
  await withSession(message, v2 ? 'l2' : 'nita', async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir);
    } catch (err) {
      await sendErr(`Fetch failed: ${err.message}`);
      return;
    }
    if (!src) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: `${cmdName} — usage`,
          description: 'Attach a `.lua`/`.luau`/`.txt` file, paste a `https://...` URL, or send a ```lua code block```.',
          color: COLORS.info,
        })],
      });
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: `Running Nita ${v2 ? 'v1+v2' : 'v1'}…`,
        description: `Source: \`${src.sourceName}\``,
        color: COLORS.info,
      })],
    });
    // v1 (always; Lune only — never any binary).
    const outV1 = path.join(sessionDir, 'recovered.lua');
    // Key-gated loaders: `.l <url> mykey` seeds script_key/SCRIPT_KEY in
    // the sandbox so key-dependent branches decrypt during tracing.
    const { key: traceKey } = parseGetArgs(message.content);
    const extraEnv = v2 ? { NITA_FORMAT: 'jsonl' } : {};
    if (traceKey && /^[A-Za-z0-9_\-]+$/.test(traceKey)) extraEnv.NITA_SCRIPT_KEY = traceKey;
    const r1 = await runLune(NITA_V1, src.inputPath, outV1, extraEnv);
    if (!fs.existsSync(outV1)) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: 'Nita failed',
          description: `Source: \`${src.sourceName}\`\n` + codePreview('', (r1.stderr || r1.stdout || (r1.err && r1.err.message) || 'unknown error').substring(0, 800), 800),
          color: COLORS.error,
        })],
      });
      return;
    }
    // V1.1: output is the executed guest's captured stdout, comments stripped.
    // No metadata wrapper, no report banner — just the result.
    const rawOutput = (() => {
      try { return fs.readFileSync(outV1, 'utf-8'); } catch { return ''; }
    })();
    const outputLines = rawOutput.split('\n').filter((l) => l.trim().length > 0);
    const hasOutput = outputLines.length > 0;
    const fields = [];
    let color = hasOutput ? COLORS.success : COLORS.warn;
    let desc = `Source: \`${src.sourceName}\`\n`;
    if (hasOutput) {
      const preview = outputLines.slice(0, 40).join('\n');
      desc += '\n```\n' + preview.substring(0, 3800) + '\n```';
    } else {
      desc += '\n*(no output)*';
    }
    const files = [];
    const skipped = [];
    maybeAttach(files, outV1, 'output.lua', skipped);
    if (v2) {
      // v2 improvement pack: replay recorder + JSONL event stream.
      // NOTE: nitav2 is a *call* recorder — a script that only sets
      // globals legitimately yields an empty replay; report honestly.
      const outV2 = path.join(sessionDir, 'replay.lua');
      await runLune(NITA_V2, src.inputPath, outV2);
      let replaySize = 0;
      try { replaySize = fs.statSync(outV2).size; } catch {}
      if (replaySize > 0) {
        maybeAttach(files, outV2, 'replay.lua', skipped);
        fields.push({ name: 'Replay', value: 'recorder ok', inline: true });
      } else {
        fields.push({ name: 'Replay', value: 'no calls to replay (globals-only — see v1 dump)', inline: false });
      }
      maybeAttach(files, outV1.replace(/\.lua$/, '.events.jsonl'), 'events.jsonl', skipped);
    }
    // Pastefy: watermarked, comment-free reconstruction (no section headers,
    // no metadata — just --[[Monke]] + clean code). Skipped for dormant
    // runs: a metadata-only paste is exactly the husk operators complain
    // about — the attached recovered.lua carries the findings instead.
    try {
      const recoveredRaw = fs.readFileSync(outV1, 'utf-8');
      const watermarked = hasOutput && recoveredRaw.trim().length > 0 ? buildWatermarkedSource(recoveredRaw) : null;
      if (watermarked) {
        const pasteUrl = await uploadPastefy(
          `recovered_${src.sourceName.replace(/\.[^.]+$/, '')}.luau`,
          watermarked,
          sessionDir
        );
        desc += `Pastefy: <${pasteUrl}>\n`;
        files.push(new AttachmentBuilder(Buffer.from(scrubSecrets(watermarked), 'utf-8'), { name: 'recovered_clean.luau' }));
      }
    } catch (err) {
      desc += `Pastefy upload skipped: \`${scrubSecrets(err.message).substring(0, 200)}\`\n`;
    }
    if (skipped.length > 0) {
      fields.push({ name: 'Skipped files', value: skipped.join('; ').substring(0, 1000), inline: false });
    }
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({
        title: v2 ? 'Nita v2 — dump + replay + events' : 'Nita V1.1',
        description: desc,
        color,
        fields,
      })],
    }, files);
  }).catch((err) => {
    console.error('[prefix] session failed:', err.message);
  });
}

async function cmdDeobfuscate(message) {
  const sendErr = (text) => replyEmbed(message, {
    embeds: [makeEmbed({ title: '.deobfuscate — error', description: text, color: COLORS.error })],
  });
  await withSession(message, 'deobf', async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir);
    } catch (err) {
      await sendErr(`Fetch failed: ${err.message}`);
      return;
    }
    if (!src) {
      // `.deobfuscate list` shows the manual picker without needing a file.
      const { hint: listHint } = parseDeobfuscateHint(message.content);
      if (/^(list|choices|options|help|endpoints)$/i.test(listHint || '')) {
        await replyEmbed(message, {
          embeds: [makeEmbed({
            title: '.deobfuscate — pick a deobfuscator',
            description: 'Skip auto-detect by naming one (works with attachment, URL, or code block):\n\n'
              + deobfuscatorChoiceList()
              + '\n\nExample: `.deobfuscate psu` + attach `script.lua`',
            color: COLORS.info,
          })],
        });
        return;
      }
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: '.deobfuscate — usage',
          description: 'Attach a `.lua`/`.luau`/`.txt` file, paste a `https://...` URL, or send a ```lua code block```.\n'
            + 'Auto-detects the obfuscator — or pick one manually: `.deobfuscate psu` + attach.\n'
            + 'See all choices: `.deobfuscate list`.',
          color: COLORS.info,
        })],
      });
      return;
    }
    if (!leakdApiKey()) {
      await sendErr('LeakD API not configured — set `LEAKD_API_KEY` in `.env` (get a key at https://discord.gg/AwGHNh7Z7T).');
      return;
    }
    const sourceCode = fs.readFileSync(src.inputPath, 'utf-8');
    if (!sourceCode || sourceCode.length === 0) {
      await sendErr('Source is empty — nothing to deobfuscate.');
      return;
    }
    const { hint: hintRaw, endpoint: hintEndpoint } = parseDeobfuscateHint(message.content);
    if (/^(list|choices|options|help|endpoints)$/i.test(hintRaw || '') && !hintEndpoint) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: '.deobfuscate — pick a deobfuscator',
          description: `Source: \`${src.sourceName}\` — or re-run naming one (skips auto-detect):\n\n`
            + deobfuscatorChoiceList(),
          color: COLORS.info,
        })],
      });
      return;
    }
    if (hintRaw && !hintEndpoint) {
      await sendErr(`Unknown deobfuscator \`${scrubSecrets(hintRaw).substring(0, 60)}\` — omit the name for auto-detect, or pick one:\n\n`
        + deobfuscatorChoiceList());
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: hintEndpoint ? 'Deobfuscating…' : 'Detecting obfuscator…',
        description: `Source: \`${src.sourceName}\`${hintEndpoint ? ` — endpoint \`${hintEndpoint}\`` : ' — LeakD `/detect`'}`,
        color: COLORS.info,
      })],
    });
    let detected = null;
    let endpoint = hintEndpoint;
    if (!endpoint) {
      try {
        detected = await leakdDetect(sourceCode, src.sourceName);
      } catch (err) {
        await editEmbed(status, {
          embeds: [makeEmbed({
            title: '.deobfuscate — auto-detect failed',
            description: `${err.message}\n\nNo problem — pick the deobfuscator yourself and re-run with the same file:\n\n`
              + deobfuscatorChoiceList(),
            color: COLORS.warn,
          })],
        });
        return;
      }
      endpoint = mapDetectorToEndpoint(detected.name);
      if (!endpoint) {
        await editEmbed(status, {
          embeds: [makeEmbed({
            title: '.deobfuscate — auto-detect unsure',
            description: `Detector said \`${scrubSecrets(detected.name).substring(0, 80)}\` — no LeakD endpoint matches it.\n`
              + 'Pick the right one yourself and re-run with the same file:\n\n'
              + deobfuscatorChoiceList(),
            color: COLORS.warn,
          })],
        });
        return;
      }
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: 'Deobfuscating…',
          description: `Source: \`${src.sourceName}\` — detected \`${scrubSecrets(detected.name).substring(0, 80)}\` → endpoint \`${endpoint}\``,
          color: COLORS.info,
        })],
      });
    }
    let data;
    try {
      data = await leakdPostFile(endpoint, sourceCode, src.sourceName);
    } catch (err) {
      const msg = String(err.message || '');
      // Wrong manual pick (or wrong auto-detect): the API says the script
      // isn't that obfuscator — invite another choice instead of dead-ending.
      const looksWrongPick = /not .*obfuscat|not moonsec|wrong obfuscator|retarded/i.test(msg);
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: '.deobfuscate — failed',
          description: msg + (looksWrongPick
            ? `\n\nWrong guess? Try another one with the same file:\n\n${deobfuscatorChoiceList()}`
            : ''),
          color: COLORS.error,
        })],
      });
      return;
    }
    const clean = leakdResultCode(data);
    if (!clean) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: '.deobfuscate — empty result',
          description: `The API returned an empty result for \`${src.sourceName}\` — nothing to attach.`,
          color: COLORS.warn,
        })],
      });
      return;
    }
    const outName = `deobfuscated_${src.sourceName.replace(/\.[^.]+$/, '')}.luau`;
    const outPath = path.join(sessionDir, outName);
    fs.writeFileSync(outPath, applyWatermark(clean), 'utf-8');
    const detName = detected ? detected.name : (hintRaw || 'explicit hint');
    const detConf = detected && detected.confidence != null ? String(detected.confidence) : '—';
    const fields = [
      { name: 'Detected', value: scrubSecrets(String(detName)).substring(0, 100), inline: true },
      { name: 'Confidence', value: detConf, inline: true },
      { name: 'Endpoint', value: endpoint, inline: true },
      { name: 'Bytes in/out', value: `${sourceCode.length} → ${clean.length}`, inline: true },
    ];
    const marked = applyWatermark(clean);
    fs.writeFileSync(outPath, marked, 'utf-8');
    let desc = `Source: \`${src.sourceName}\` — Result: \`${marked.length}\` bytes\n\n`
      + codePreview('lua', marked, 1300);
    const files = [];
    maybeAttach(files, outPath, outName);
    if (files.length === 0) {
      desc += `\nToo big for Discord — attaching a link instead.\n`;
    } else {
      desc += `\nFile attached: \`${outName}\`\n`;
    }
    try {
      const pasteUrl = await publishPastefy(outName, marked, sessionDir);
      if (pasteUrl) desc += `\nFull source: <${pasteUrl}>\n`;
    } catch (err) {
      desc += `\nPastefy upload failed: \`${scrubSecrets(err.message).substring(0, 160)}\`\n`;
    }
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({ title: 'Deobfuscated', description: desc, color: COLORS.success, fields })],
    }, files.slice(0, 10));
  }).catch((err) => {
    console.error('[prefix] session failed:', err.message);
  });
}

async function cmdDetect(message) {
  const sendErr = (text) => replyEmbed(message, {
    embeds: [makeEmbed({ title: '.detect — error', description: text, color: COLORS.error })],
  });
  await withSession(message, 'detect', async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir);
    } catch (err) {
      await sendErr(`Fetch failed: ${err.message}`);
      return;
    }
    if (!src) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: '.detect — usage',
          description: 'Attach a `.lua`/`.luau`/`.txt` file, paste a `https://...` URL, or send a ```lua code block```.',
          color: COLORS.info,
        })],
      });
      return;
    }
    if (!leakdApiKey()) {
      await sendErr('LeakD API not configured — set `LEAKD_API_KEY` in `.env` (get a key at https://discord.gg/AwGHNh7Z7T).');
      return;
    }
    const sourceCode = fs.readFileSync(src.inputPath, 'utf-8');
    if (!sourceCode || sourceCode.length === 0) {
      await sendErr('Source is empty — nothing to check.');
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: 'Detecting…',
        description: `Source: \`${src.sourceName}\` — LeakD \`/detect\``,
        color: COLORS.info,
      })],
    });
    let detected;
    try {
      detected = await leakdDetect(sourceCode, src.sourceName);
    } catch (err) {
      await editEmbed(status, {
        embeds: [makeEmbed({ title: '.detect — failed', description: err.message, color: COLORS.error })],
      });
      return;
    }
    const endpoint = mapDetectorToEndpoint(detected.name);
    const conf = detected.confidence != null ? String(detected.confidence) : '—';
    const fields = [
      { name: 'Obfuscator', value: scrubSecrets(detected.name).substring(0, 200), inline: true },
      { name: 'Confidence', value: conf, inline: true },
      { name: 'Endpoint', value: endpoint || 'none (unsupported)', inline: true },
    ];
    let desc = `Source: \`${src.sourceName}\` — **${scrubSecrets(detected.name).substring(0, 120)}** (confidence: \`${conf}\`)\n`;
    if (endpoint === '/luraphv15') desc += 'Suggested: `.luraph` (or `.deobfuscate` — routes to `/luraphv15`)\n';
    else if (endpoint) desc += `Suggested: \`.deobfuscate\` (routes to \`${endpoint}\`)\n`;
    else desc += `No LeakD endpoint matches — supported: ${supportedEndpointList()}.\n`;
    desc += '_Note: the detector lags new obfuscators per LeakD docs — treat low-confidence results as hints._';
    await editEmbed(status, {
      embeds: [makeEmbed({ title: 'Detector — result', description: desc, color: endpoint ? COLORS.success : COLORS.warn, fields })],
    });
  }).catch((err) => {
    console.error('[prefix] session failed:', err.message);
  });
}

// ---- Fetch + unpack arg parsing (shared by .get / .get2 / .luarmor / .jnkie)
// Usage: .get <url> [key]  |  .get <url1> <url2> [--key KEY]  |  .get key=KEY <url>
//   * URL is REQUIRED (1-5 http(s) loader URLs).
//   * Key is OPTIONAL - omit it for keyless scripts, or pass it explicitly.
const MAX_LOADER_URLS = 5;
// Inputs up to ~2MB get unpacked (800KB-2MB uses the static-only tier:
// clean + harvest + stages, no sandboxed execution). Bigger ones attach
// raw and count as failed-unpack - honestly.
const MAX_UNPACK_BYTES = 2 * 1024 * 1024;
const STATIC_ONLY_BYTES = 800 * 1024;
// Loadstring stage resolution (`.get`): executes a fetched loader in the
// sandbox so stages it builds at runtime become followable. Kept under the
// static-only ceiling because the point is following a loader, not lifting a
// large payload — big payloads stay on the raw/static path.
const LOADSTRING_MAX_BYTES = 800 * 1024;
const LOADSTRING_TIMEOUT_MS = 45000;
const LOADSTRING_MIN_BUDGET_MS = 15000;
// Local unpacker run budget; the OS kill is the hard guard.
const UNPACK_TIMEOUT_MS = 195000;

function parseGetArgs(content) {
  const after = String(content || '').split(/\s+/).slice(1).join(' ');
  const urls = extractUrls(after).slice(0, MAX_LOADER_URLS);
  // Explicit key forms: key=VAL, --key VAL, -k VAL (first wins).
  let key = null;
  let m = after.match(/\bkey\s*=\s*([^\s<>"'`]+)/i) || after.match(/--key\s+([^\s<>"'`]+)/i)
    || after.match(/(?:^|\s)-k\s+([^\s<>"'`]+)/i);
  if (m) {
    key = m[1].replace(/[<>"'`]+/g, '').replace(/[).,\];!]+$/, '');
  } else {
    // Bare second token treated as key: `.get <url> <key>` (key must not
    // look like a URL and must not be inside a code block).
    const noUrls = after.replace(/https?:\/\/[^\s<>"'`]+/gi, ' ');
    const noBlocks = noUrls.replace(/```[\s\S]*?```/g, ' ');
    // Strip CLI flags AND their values before looking for a bare key token,
    // otherwise `.get <url> --depth 5` reports the key as "--depth".
    const noFlags = noBlocks
      .replace(/(?:^|\s)(--[A-Za-z][\w-]*)(?:\s+\S+)?/g, ' ')
      .replace(/(?:^|\s)-[A-Za-z]\b/g, ' ');
    const tokens = noFlags.split(/\s+/)
      .map((t) => t.trim().replace(/^<+/, '').replace(/>+$/, '').replace(/[).,\];!]+$/, ''))
      .filter((t) => t && t !== '.get' && !/^(--key|-k|key=)$/i.test(t) && !/^key=/i.test(t));
    if (tokens.length > 0) key = tokens[0];
  }
  if (key) key = key.trim();
  return { urls, key: key || '' };
}

function extractCodeBlock(text) {
  const src = String(text || '');
  // Greedy, not lazy: obfuscated sources routinely contain ``` inside string
  // literals, and a lazy match would close the block at the first one and
  // hand us a truncated (unparseable) script. Anchor the terminator to the
  // final fence instead, so embedded fences stay inside the code.
  const m = src.match(/```(?:lua|luau)?\s*\n([\s\S]*)```/i);
  return m ? m[1].trim() : null;
}

// ---- Provider error hints --------------------------------------------------
// Providers answer with terse error text. Turn the common ones into advice,
// since "Invalid session" on its own tells the user nothing about what to do.
function fetchHint(message) {
  const m = String(message || '');
  if (/invalid session|session (?:expired|invalid)/i.test(m)) {
    return 'this fetcher link is **single-use** — it was already consumed (or has expired). Copy a fresh one from the loader/executor and send it again.';
  }
  if (/expired|token (?:expired|stale)/i.test(m)) {
    return 'the provider rejected this as stale. Re-copy the URL; loader blobs often rotate hourly.';
  }
  if (/key required|script_key|unauthorized|forbidden|401|403/i.test(m)) {
    return 'the provider wants a script key. Re-run with the key: `.get <url> <key>`';
  }
  if (/captcha|bot.?signal|browser.?fingerprint|cloudflare/i.test(m)) {
    return 'the provider put an active bot gate in front of this URL (captcha / bot-signal). That has to be solved by a real client, so no header we send will clear it.';
  }
  if (/not found|404/i.test(m)) {
    return 'that path does not exist on the provider — check the URL was copied whole.';
  }
  if (/rate limit|too many|429/i.test(m)) {
    return 'rate limited by the provider. Wait a few minutes and retry.';
  }
  if (/blocked|forbidden ip|datacenter/i.test(m)) {
    return 'the provider blocks this IP range (common for datacenter hosts), so no client profile will get through.';
  }
  return null;
}

// ---- Jnkie delivery chain --------------------------------------------------
// A Jnkie loader does not contain the payload: it points at a delivery API
// that hands back a CDN URL only when you POST the script key. That is the
// provider's own documented flow, so we perform it — with two deliberate
// differences from the reference script this was based on:
//
//   * The key comes ONLY from the user's own message. The reference looked the
//     key up in process.env by variable name and POSTed it to a third party,
//     which on this bot would have shipped a bot secret to jnkie.com.
  //   * The POST goes through postUrlSafe (DNS pinning, public-IP enforcement,
  //     IP-logger refusal, size cap) pinned to the jnkie API host, and the
  //     returned URL is only
//     followed when it is on cdn.jnkie.com.
const JNKIE_DELIVERY_RE = /https:\/\/api\.jnkie\.com\/api\/v1\/luascripts\/delivery\/[^\s"'\\]+/i;
const JNKIE_CDN_RE = /^https:\/\/cdn\.jnkie\.com\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/;

function fetchJnkieDelivery(loaderBody, { key, budgetMs = 45000, preferredProfile = null } = {}) {
  const m = JNKIE_DELIVERY_RE.exec(String(loaderBody || ''));
  if (!m) return null;
  const deliveryUrl = m[0];
  return (async () => {
    const post = await postUrlSafe(deliveryUrl, {
      body: key || '',
      timeoutMs: Math.min(20000, Math.max(3000, budgetMs - 5000)),
      maxBytes: 64 * 1024,
      contentType: 'text/plain',
      allowHosts: ['api.jnkie.com', 'jnkie.com'],
      headers: {
        'User-Agent': 'Roblox/WinInet',
        'Accept': 'application/json, text/plain, */*',
      },
    });
    const notes = [`delivery API -> HTTP ${post.statusCode}`];
    if (post.statusCode !== 200) {
      return { ok: false, deliveryUrl, notes, error: `delivery API returned HTTP ${post.statusCode}` };
    }
    // The API answers with a bare CDN URL. Anything else is not a payload
    // pointer, so do not follow it.
    const cdn = post.body.trim();
    if (!JNKIE_CDN_RE.test(cdn)) {
      return { ok: false, deliveryUrl, notes, error: 'delivery response was not a cdn.jnkie.com URL' };
    }
    notes.push(`payload URL: ${cdn}`);
    if (budgetMs <= 5000) return { ok: false, deliveryUrl, notes, error: 'no time left to fetch the payload' };
    const got = await fetchEscalating(cdn, {
      maxBytes: MAX_SOURCE_BYTES,
      budgetMs: Math.min(budgetMs, 45000),
      accept: (b) => classifyBody(b).ok,
      preferredProfile,
    });
    for (const t of (got.tried || [])) notes.push(`  ${t}`);
    if (!got.body) {
      return { ok: false, deliveryUrl, notes, error: got.error ? got.error.message : 'CDN payload was not a script' };
    }
    return { ok: true, deliveryUrl, cdnUrl: cdn, body: got.body, notes };
  })();
}

// ---- Three-tier escalating fetch -----------------------------------------
// Repeating the same request three times only helps a flaky network, so each
// attempt is a materially different strategy:
//
//   1. normal      — base client profile, short timeout. The common case.
//   2. deep        — a different client identity, a longer timeout, and one
//                    extra redirect hop. Providers that pin a client family or
//                    bounce via a CDN answer here.
//   3. final boss  — every remaining identity, the longest timeout, a same-origin
//                    Referer, and for a payload that is not readable source a
//                    decode-and-retry pass (hex / base64 layers) that digs for an
//                    inner URL.
//
// A transient blip still retries once inside whichever tier it happened in, so
// a dropped connection does not burn an escalation.
const ESCALATION_TIERS = [
  { name: 'normal', profiles: ['win'], timeoutMs: 12000, referer: false, deep: false },
  { name: 'deep', profiles: ['mac', 'xbox'], timeoutMs: 25000, referer: true, deep: false },
  { name: 'final', profiles: ['studio', 'mobile', 'win'], timeoutMs: 45000, referer: true, deep: true },
];

function sameOriginReferer(url) {
  try { return `${new URL(url).origin}/`; } catch { return null; }
}

// One network try with a specific identity.
async function fetchOnceTier(url, { maxBytes, profile, timeoutMs, referer }) {
  const headers = { ...ROBLOX_HEADERS, ...(CLIENT_PROFILES[profile] || {}) };
  if (referer) {
    const r = sameOriginReferer(url);
    if (r) headers.Referer = r;
  }
  return fetchUrlSafe(url, { timeoutMs, maxBytes, headers });
}

// Decode a payload looking for an inner URL worth fetching. Used by the final
// tier only: a provider that answers with ciphertext may still have the next
// stage embedded in it.
function deepUnwrap(body) {
  const raw = String(body == null ? '' : body);
  if (!raw) return [];
  const tries = [raw];
  // Layer 1: Lua \xNN escapes.
  tries.push(raw.replace(/\\x([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))));
  // Layer 2: long base64 literals, decoded as latin-1.
  for (const b64 of raw.match(/[A-Za-z0-9+/\n]{300,}={0,2}/g) || []) {
    try {
      const buf = Buffer.from(b64.replace(/\s+/g, ''), 'base64');
      if (buf.length > 32) tries.push(buf.toString('latin1'));
    } catch { /* not base64 */ }
  }
  const seen = new Set();
  const urls = [];
  for (const layer of tries) {
    for (const u of harvestStageUrls(layer, { limit: 4 })) {
      if (seen.has(u)) continue;
      seen.add(u);
      urls.push(u);
    }
  }
  return urls;
}

// Keep escalating through distinct identities, but try the user's selected
// profile first inside every tier. Without this the --xbox/--mac/--studio/
// --mobile flag was parsed and then ignored by `.get`.
function orderedProfiles(profiles, preferredProfile) {
  const list = Array.isArray(profiles) ? [...profiles] : [];
  if (!preferredProfile) return list;
  const rest = list.filter((p) => p !== preferredProfile);
  return list.includes(preferredProfile) ? [preferredProfile, ...rest] : [preferredProfile, ...rest];
}

// `accept(body)` decides whether a fetched payload is good enough. Tiers 1 and
// 2 stop at the first acceptable body; tier 3 additionally digs into a payload
// that is NOT acceptable (e.g. a provider handed back an encrypted container
// instead of the script) looking for an inner URL worth fetching.
async function fetchEscalating(url, { maxBytes, budgetMs, accept, log = [], preferredProfile = null } = {}) {
  const started = Date.now();
  const ok = typeof accept === 'function' ? accept : () => true;
  const dead = () => (budgetMs ? Date.now() - started > budgetMs : false);
  const leftMs = (want) => (budgetMs
    ? Math.max(2000, Math.min(want, budgetMs - (Date.now() - started)))
    : want);
  let lastErr = null;
  let lastBody = null;
  // Consensus short-circuit: when two or more DIFFERENT client identities get
  // back the same definitive non-script verdict, more identities will not help.
  //
  // Identity escalation exists for hosts that answer some clients with a small
  // guard and others with the real payload. But when the answer is an HTML
  // page or a JSON blob, it is the same for every client — retrying tiers 2 and
  // 3 just burns wall-clock and produces noisy duplicate failures. Requires an
  // actual body each time, so a network failure never trips it.
  let consensusKind = null;
  let consensusCount = 0;

  for (let t = 0; t < ESCALATION_TIERS.length; t++) {
    const tier = ESCALATION_TIERS[t];
    if (t > 0 && dead()) { log.push(`tier ${t + 1} skipped — time budget spent`); break; }

    for (const profile of orderedProfiles(tier.profiles, preferredProfile)) {
      if (dead()) { log.push(`tier ${t + 1} stopped early — time budget spent`); break; }
      try {
        const body = await fetchOnceTier(url, {
          maxBytes, profile, timeoutMs: leftMs(tier.timeoutMs), referer: tier.referer,
        });
        if (ok(body)) {
          log.push(`tier ${t + 1} (${tier.name}) as ${profile}: ${body.length} bytes`);
          return { body, tier: t + 1, tierName: tier.name, profile, tried: log, elapsedMs: Date.now() - started };
        }
        if (!lastBody) lastBody = body;
        const why = classifyBody(body);
        log.push(`tier ${t + 1} as ${profile}: ${body.length} bytes but not a script`);
        if (why && why.ok === false) {
          if (why.kind === consensusKind) {
            consensusCount += 1;
          } else {
            consensusKind = why.kind;
            consensusCount = 1;
          }
          if (consensusCount >= 2) {
            log.push(`stopped after ${consensusCount} identities agreed: ${why.reason}`);
            return {
              body: null,
              rejected: why.reason,
              consensus: true,
              consensusKind: why.kind,
              tried: log,
              elapsedMs: Date.now() - started,
            };
          }
        }
      } catch (err) {
        lastErr = err;
        log.push(`tier ${t + 1} (${tier.name}) as ${profile}: ${(err.message || '').substring(0, 90)}`);
        if (TRANSIENT_RE.test(err.message || '')) {
          await sleepMs(300);
          if (!dead()) {
            try {
              const body = await fetchOnceTier(url, {
                maxBytes, profile, timeoutMs: leftMs(tier.timeoutMs), referer: tier.referer,
              });
              if (ok(body)) {
                log.push(`tier ${t + 1} retry as ${profile}: ${body.length} bytes`);
                return { body, tier: t + 1, tierName: tier.name, profile, retried: true, tried: log, elapsedMs: Date.now() - started };
              }
              if (!lastBody) lastBody = body;
            } catch (err2) {
              lastErr = err2;
              log.push(`tier ${t + 1} retry as ${profile}: ${(err2.message || '').substring(0, 90)}`);
            }
          }
        }
      }
    }

    if (tier.deep && lastBody && lastBody.length) {
      const inner = deepUnwrap(lastBody);
      log.push(`tier 3 deep pass: ${inner.length} candidate inner URL(s)`);
      for (const u of inner.slice(0, 2)) {
        if (dead() || u === url) continue;
        try {
          const body = await fetchOnceTier(u, {
            maxBytes, profile: preferredProfile || 'win', timeoutMs: leftMs(30000), referer: true,
          });
          if (ok(body)) {
            log.push(`tier 3 deep: fetched ${u} (${body.length} bytes)`);
            return { body, tier: 3, tierName: 'final', profile: preferredProfile || 'win', unwrappedFrom: u, tried: log, elapsedMs: Date.now() - started };
          }
        } catch (err) {
          log.push(`tier 3 deep: ${u} -> ${(err.message || '').substring(0, 70)}`);
        }
      }
    }
  }
  // Fetched fine but the content is not readable source: say WHICH kind.
  let rejected = null;
  if (lastBody && !ok(lastBody)) {
    const why = classifyBody(lastBody);
    rejected = (why && why.reason) ? why.reason : 'payload was not readable source';
  }
  return { body: null, error: lastErr, rejected, tried: log, elapsedMs: Date.now() - started };
}

// ---- Harness scaffolding ---------------------------------------------------
// The local Luraph v15 pipeline emits the sandbox's own preamble alongside the
// lifted code: no-op network shims (getgenv().request = function() end),
// Luarmor's _bsdata0 handoff blob, and the injected SCRIPT_KEY. None of that
// belongs in a "deobfuscated script" deliverable.
const HARNESS_PATH_RE = /^\s*--\s*\/tmp\/deobf_node_[^\s:]*[:/]/;

// Line-based removal: a shim assignment spans multiple lines
// (`X.request = function(a, b)` ... `end`), so track the construct instead of
// guessing at blank-line-separated blocks.
function stripHarnessScaffolding(code) {
  const src = String(code == null ? '' : code);
  const lines = src.split('\n');
  const out = [];
  let droppedBlocks = 0;
  let i = 0;
  const SHIM_START = /^(?:getgenv\(\)|_G|shared|env)(?:\.[A-Za-z_][\w.]*)*\s*=\s*(?:function\b|\{|table\b|\{)/;
  // Matches both a bare `SCRIPT_KEY = "x"` and the receiver form the harness
  // actually emits: `getgenv().SCRIPT_KEY = "x"`.
  const KEY_START = /^(?:\s*(?:local\s+)?|(?:getgenv\(\)|_G|shared|env)\.)(?:SCRIPT_?KEY|LRM_SCRIPT_?KEY)\s*=/i;
  while (i < lines.length) {
    const line = lines[i];
    if (HARNESS_PATH_RE.test(line) || /^-{2,}\s*$/.test(line.trim())) { i++; continue; }
    if (SHIM_START.test(line.trim()) || KEY_START.test(line)) {
      // A `= function(...)` construct closes with `end`; a `= {` construct
      // closes with `}`. Matching the wrong one leaves a stray brace behind.
      const isTable = /=\s*(?:table\b|\{)\s*$/.test(line.trim());
      const oneLine = KEY_START.test(line) && !/\b(?:function|\{|table\b)\s*$/.test(line.trim());
      let closed = oneLine;
      let j = i;
      if (!closed) {
        const closer = isTable ? /^\};?$/ : /^end$/;
        for (; j < lines.length; j++) {
          if (closer.test(lines[j].trim())) { closed = true; break; }
          // Safety: an unterminated construct must not eat the rest of the file.
          if (j - i > 200) break;
        }
      }
      droppedBlocks++;
      i = Math.min(lines.length, j + 1);
      if (i < lines.length && lines[i].trim() === '') i++;
      continue;
    }
    out.push(line);
    i++;
  }
  const text = out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
  return { text, droppedBlocks };
}

// After scaffolding is gone, is anything real left? If the file is only
// comments and error() stubs, no source was lifted and the reply must say so.
function looksLikeScaffoldOnly(code) {
  const meaningful = String(code || '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('--'));
  if (!meaningful.length) return true;
  return meaningful.every((l) => (
    /^error\(/.test(l)
    || /^local function luraph_runtime/.test(l)
    || /^end$/.test(l)
    || /^local [\w.]+\s*=\s*\{?\}?$/.test(l)
    || /^(?:return|\)|\}|\{)$/.test(l)
  ));
}

// What did the local pipeline actually achieve? The output can be a genuine
// lift, only harness scaffolding, or an explicit devirtualization failure —
// and those must not all be reported as "deobfuscated".
function analyzeLocalResult(code) {
  const text = String(code || '');
  const scaffoldOnly = looksLikeScaffoldOnly(text);
  const devirtFailed = /error\(\s*["']devirt:|not devirtualized|unexplored successor/i.test(text);
  const liftedLines = text.split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('--')
      && !/^error\(/.test(l) && !/^local function luraph_runtime/.test(l)
      && !/^(?:end|return|\)|\}|\{)$/.test(l)).length;
  return { scaffoldOnly, devirtFailed, liftedLines, useful: !scaffoldOnly && !devirtFailed && liftedLines > 3 };
}

// Fetch-only flavors: grab raw files and never invoke the unpacker. `.get2`
// is `.get` plus the Jnkie delivery chain.
const FETCH_ONLY_FLAVORS = new Set(['get', 'get2']);

function flavorUsage(flavor) {
  const f = FLAVORS[flavor] || FLAVORS.get;
  const cmd = `.${flavor}`;
  return f.usage +
    'Examples:\n' +
    `\`${cmd} https://api.luarmor.net/files/v3/loaders/xxxx.lua\`\n` +
    `\`${cmd} https://api.luarmor.net/files/v3/loaders/xxxx.lua mykey123\`\n` +
    `\`${cmd} https://.../a.lua https://.../b.lua --key mykey123\``;
}

async function cmdFetchUnpack(message, flavor) {
  const F = FLAVORS[flavor] || FLAVORS.get;
  const USAGE = flavorUsage(flavor);
  const cmdTag = `.${flavor}`;
  const sendUsage = (extra) => replyEmbed(message, {
    embeds: [makeEmbed({
      title: `${cmdTag} — usage`,
      description: (extra ? extra + '\n' : '') + USAGE,
      color: COLORS.info,
    })],
  });
  const { urls, key } = parseGetArgs(message.content);
  if (urls.length === 0) {
    await sendUsage();
    return;
  }
  if (key && !/^[A-Za-z0-9_\-]+$/.test(key)) {
    await sendUsage(`Invalid key \`${scrubSecrets(key).substring(0, 60)}\` — use only letters, numbers, \`_\` and \`-\`.`);
    return;
  }
  for (const u of urls) {
    if (u.length > 2000) {
      await sendUsage('One of the URLs is too long (max 2000 chars).');
      return;
    }
  }
  const profileName = clientProfileName(message.content);
  await withSession(message, F.tag, async (sessionDir) => {
    // Fetch-only flavors grab raw files; the unpacker flavors run luarmor.lua.
    const plainFetch = FETCH_ONLY_FLAVORS.has(flavor);
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: `${F.title} — working…`,
        description: plainFetch
          ? `Fetching ${urls.length} URL${urls.length > 1 ? 's' : ''}…`
          : `Fetching + unpacking ${urls.length} URL${urls.length > 1 ? 's' : ''} locally…`,
        color: COLORS.info,
      })],
    });
    const loader = buildLoaderSource(urls, key);
    const loaderPath = path.join(sessionDir, 'loader.lua');
    fs.writeFileSync(loaderPath, loader, 'utf-8');

    const MAX_STAGE_DEPTH = clampInt(valFlag(message.content, '--depth'), 3, 0, 8);
    const MAX_PROCESSED = clampInt(valFlag(message.content, '--max'), 10, 1, 40);
    // Overall wall-clock budget. Without it a pathological chain could run for
    // ten minutes; the escalating fetch is bounded by this too.
    const RUN_BUDGET_MS = clampInt(valFlag(message.content, '--budget'), 150, 20, 900) * 1000;
    const runStarted = Date.now();
    const budgetLeft = () => Math.max(0, RUN_BUDGET_MS - (Date.now() - runStarted));

    const files = [];
    const lines = [];
    let firstClean = null;
    let succeeded = 0;
    let failed = 0;
    const seen = new Set();
    const queue = urls.map((u) => ({ url: u, depth: 0 }));
    const numbers = new Map();
    urls.forEach((u, i) => numbers.set(u, String(i + 1)));
    // Soft flavor check: note (don't refuse) URLs that don't look like the
    // command's provider.
    if (F.hint) {
      const alt = F.hint === 'luarmor' ? 'jnkie' : 'luarmor';
      urls.forEach((u, i) => {
        const low = u.toLowerCase();
        const likeThis = F.hint === 'luarmor'
          ? (low.includes('luarmor') || low.includes('cdn.luarmor.net'))
          : (low.includes('jnkie') || low.includes('junkie'));
        const likeAlt = low.includes(alt);
        if (!likeThis) {
          lines.push(`${i + 1}. <${u}> — note: URL doesn't look like ${F.hint}${likeAlt ? ` (looks like ${alt} — try \`.*${alt}*\`)` : ''}, processing anyway`);
        }
      });
    }
    let counter = 0;
    let processed = 0;
    let totalBytes = 0;
    let retried = 0;
    let escalated = 0;
    let containers = 0;
    let jnkieChains = 0;
    let jnkieFailed = 0;
    let maxDepth = 0;
    let loadstringRuns = 0;
    let loadstringResolved = 0;
    // Scripts worth handing to the obfuscator detector, biggest first.
    const detectCandidates = [];
    // Largest fetched script, which is what the user actually wants to see —
    // the first stage is usually a tiny loader stub.
    let biggest = null;
    let biggestLabel = '';
    while (queue.length > 0 && processed < MAX_PROCESSED) {
      const item = queue.shift();
      if (seen.has(item.url)) continue;
      seen.add(item.url);
      processed++;
      counter++;
      const label = numbers.has(item.url) ? numbers.get(item.url) : `S${counter}`;
      let body;
      let bodyClass = null;
      let tierUsed = 0;
      const attemptLog = [];
      try {
        if (budgetLeft() <= 2000) throw new Error('out of time budget before this URL');
        const got = await fetchEscalating(item.url, {
          maxBytes: MAX_SOURCE_BYTES,
          budgetMs: Math.min(budgetLeft(), 60000),
          // A protected container IS a legitimate result, so accept it here and
          // let the caller label it; only HTML/JSON/prose force escalation.
          accept: (b) => classifyBody(b).ok,
          log: attemptLog,
          preferredProfile: profileName,
        });
        if (!got.body) {
          throw new Error(got.error ? got.error.message : (got.rejected || 'empty body'));
        }
        body = got.body;
        tierUsed = got.tier || 0;
        if (got.tier > 1) escalated++;
        if (got.retried) retried++;
        bodyClass = classifyBody(body);
        totalBytes += Buffer.byteLength(body, 'utf-8');
      } catch (err) {
        failed++;
        lines.push(`${label}. <${item.url}> — FAILED (fetch): \`${scrubSecrets(err.message).substring(0, 160)}\``);
        for (const a of attemptLog.slice(-6)) lines.push(`    · ${a}`);
        const hint = fetchHint(err.message);
        if (hint) lines.push(`    → ${hint}`);
        continue;
      }
      const stageInput = path.join(sessionDir, `stage_${counter}.lua`);
      fs.writeFileSync(stageInput, body, 'utf-8');
      if (plainFetch) {
        // Fetch-only: hand over the raw file. No unpacking — but DO follow
        // the chain, otherwise `.get` can only ever return the URLs the user
        // typed. Next stages are discovered statically from the source.
        if (bodyClass && bodyClass.kind === 'container') {
          // Protected payload: keep the bytes, but do not pretend it is Lua
          // and do not try to mine next-stage URLs out of ciphertext.
          const binName = `fetched_${counter}.bin`;
          fs.writeFileSync(path.join(sessionDir, binName), body, 'latin1');
          if (firstClean === null) firstClean = '';
          if (!biggest || body.length > biggest.length) { biggest = ''; biggestLabel = `${label} (${item.url})`; }
          if (item.depth > maxDepth) maxDepth = item.depth;
          containers++;
          succeeded++;
          lines.push(`${label}. <${item.url}> — FETCHED \`${body.length}\` bytes${tierUsed > 1 ? ` (attempt ${tierUsed}/${ESCALATION_TIERS.length})` : ''} — **${bodyClass.label}**: encrypted/compiled, so there is no source to read here. Saved as \`${binName}\`; it needs the provider's loader to decrypt (run it in Roblox with your key).`);
            continue;
        }
        const outName = `fetched_${counter}.lua`;
        fs.writeFileSync(path.join(sessionDir, outName), body, 'utf-8');
        if (firstClean === null) firstClean = body;
        if (!biggest || body.length > biggest.length) { biggest = body; biggestLabel = `${label} (${item.url})`; }
        if (item.depth > maxDepth) maxDepth = item.depth;
        detectCandidates.push({ label, url: item.url, body });
        succeeded++;
        const exec = identifyExecutor(body);
        const stages = (item.depth + 1 < MAX_STAGE_DEPTH)
          ? harvestStageUrls(body, { limit: 6, exclude: [...seen] })
          : [];

        // Loadstring resolution: a loader that builds its next URL with
        // string.char/table.concat (or inside a VM) hides it from static
        // harvesting, so the chain silently stops after stage 1. Run the
        // sandboxed unpacker to execute the loader's loadstring path and read
        // the stages it actually requests.
        //
        // Default is FALLBACK-ONLY: when static harvesting already found
        // stages there is nothing to gain, and the unpacker is expensive, so
        // the common case stays fast. `--loadstring` forces it on every
        // stage, `--no-loadstring` turns it off entirely.
        const allStages = [...stages];
        let loadstringRan = false;
        let loadstringStages = [];
        let loadstringCleanBytes = 0;
        let rejectedStages = [];
        const forceLoadstring = hasFlag(message.content, '--loadstring');
        const allowLoadstring = !hasFlag(message.content, '--no-loadstring');
        const wantLoadstring = allowLoadstring
          && (forceLoadstring || stages.length === 0)
          && item.depth + 1 < MAX_STAGE_DEPTH
          && body.length <= LOADSTRING_MAX_BYTES;
        if (wantLoadstring && budgetLeft() > LOADSTRING_MIN_BUDGET_MS) {
          loadstringRan = true;
          loadstringRuns++;
          const lsDir = path.join(sessionDir, `loadstring_${counter}`);
          const lsTimeout = Math.min(LOADSTRING_TIMEOUT_MS, Math.max(5000, budgetLeft() - 5000));
          // NITA_STAGE_STUB=1: answer the loader's HTTP reads with an inert
          // but valid Lua chunk so `loadstring(game:HttpGet(url))()` proceeds
          // instead of dying on `loadstring("")`.
          await runUnpacker(stageInput, lsDir, key, false, lsTimeout, { NITA_STAGE_STUB: '1' });
          const lsInfo = readStagesJson(lsDir);
          // Apply the same script-likeness bar as static discovery. Without
          // this the sandbox handed us the loader's own API base and session
          // endpoints, which were queued and then failed as HTML/JSON.
          const rejectedStages = [];
          loadstringStages = lsInfo.stages
            .map((s) => s.url)
            .filter((u) => {
              if (typeof u !== 'string' || u.length > 2000 || seen.has(u) || allStages.includes(u)) return false;
              if (!scriptLikeUrl(u)) {
                rejectedStages.push(u);
                return false;
              }
              return true;
            });
          // Keep the resolved body: it is the loader's own output, which is
          // what the chain was actually asking for.
          try {
            const lsClean = path.join(lsDir, 'clean.lua');
            if (fs.existsSync(lsClean)) {
              const bodyText = fs.readFileSync(lsClean, 'utf-8');
              if (bodyText && bodyText.length > 0) {
                loadstringCleanBytes = Buffer.byteLength(bodyText, 'utf-8');
                fs.writeFileSync(path.join(sessionDir, `loadstring_${counter}.luau`), bodyText, 'utf-8');
              }
            }
          } catch { /* best-effort: stages are the important result */ }
          for (const u of loadstringStages) allStages.push(u);
          loadstringResolved += loadstringStages.length;
        }

        // .get2 only: complete a Jnkie delivery chain when the loader points at
        // one. The payload replaces the stub as the interesting result.
        if (flavor === 'get2' && JNKIE_DELIVERY_RE.test(body) && budgetLeft() > 6000) {
          const chain = await fetchJnkieDelivery(body, { key, budgetMs: budgetLeft() - 3000, preferredProfile: profileName });
          if (chain && chain.ok) {
            const payloadPath = path.join(sessionDir, `jnkie_payload_${counter}.lua`);
            fs.writeFileSync(payloadPath, chain.body, 'latin1');
            fs.writeFileSync(path.join(sessionDir, `fetched_${counter}.lua`), chain.body, 'utf-8');
            if (firstClean === null) firstClean = chain.body;
            if (!biggest || chain.body.length > biggest.length) {
              biggest = chain.body;
              biggestLabel = `Jnkie payload via ${label}`;
            }
            jnkieChains++;
            for (const n of (chain.notes || [])) lines.push(`    · ${n}`);
            lines.push(`${label}. <${item.url}> — JNKEY CHAIN COMPLETE: payload \`${chain.body.length}\` bytes from \`${chain.cdnUrl}\``);
            continue;
          }
          if (chain) {
            jnkieFailed++;
            for (const n of (chain.notes || [])) lines.push(`    · ${n}`);
            lines.push(`${label}. Jnkie chain incomplete: ${chain.error} — the raw loader is still attached.`);
          }
        }

        let extra = `fetched \`${body.length}\` bytes`;
        if (exec.verdict !== 'unknown / no executor globals detected') extra += `, client: ${exec.verdict}`;
        if (stages.length) extra += `, ${stages.length} next-stage URL(s) found`;
        if (loadstringRan) {
          if (loadstringStages.length) {
            extra += `, loadstring resolved ${loadstringStages.length} more stage(s)`;
          } else {
            extra += `, loadstring pass found nothing more`;
          }
        }
        if (loadstringCleanBytes > 0) extra += `, resolved body saved as \`loadstring_${counter}.luau\``;
        if (tierUsed > 1) extra += `, got it on attempt ${tierUsed}/${ESCALATION_TIERS.length}`;
        lines.push(`${label}. <${item.url}> — SUCCESS: ${extra}`);
        if (loadstringStages.length) {
          for (const u of loadstringStages) lines.push(`    · loadstring stage (speculative): <${u}>`);
        }
          if (rejectedStages.length) {
            for (const u of rejectedStages.slice(0, 4)) {
              lines.push(`    · ignored non-script stage: <${u}>`);
            }
          }
        for (const u of allStages) {
          if (!seen.has(u) && u.length <= 2000) queue.push({ url: u, depth: item.depth + 1 });
        }
        continue;
      }
      if (body.length > MAX_UNPACK_BYTES) {
        // Over ~2MB: attach raw, count as failed-unpack (honest).
        failed++;
        fs.writeFileSync(path.join(sessionDir, `fetched_${counter}.lua`), body, 'utf-8');
        lines.push(`${label}. <${item.url}> — FAILED (unpack: over 2MB limit): fetched \`${body.length}\` bytes, raw attached`);
        continue;
      }
      // 800KB–2MB tier: static-only (no sandboxed execution); the driver
      // still cleans, harvests layers, and extracts stages.
      const staticOnly = body.length > STATIC_ONLY_BYTES;
      const unpackDir = path.join(sessionDir, `unpack_${counter}`);
      await runUnpacker(stageInput, unpackDir, key, staticOnly);
      let clean = null;
      try {
        const cp = path.join(unpackDir, 'clean.lua');
        if (fs.existsSync(cp) && fs.statSync(cp).size > 0) clean = fs.readFileSync(cp, 'utf-8');
      } catch { /* treated as unpack failure below */ }
      if (clean === null) {
        failed++;
        fs.writeFileSync(path.join(sessionDir, `fetched_${counter}.lua`), body, 'utf-8');
        lines.push(`${label}. <${item.url}> — FAILED (unpack): fetched \`${body.length}\` bytes, see file`);
        continue;
      }
      const stages = readStagesJson(unpackDir);
      const facts = readUnpackFacts(unpackDir);
      const outName = `deobfuscated_${counter}.luau`;
      fs.writeFileSync(path.join(sessionDir, outName), clean, 'utf-8');
      if (firstClean === null) firstClean = clean;
      if (item.depth > maxDepth) maxDepth = item.depth;
      succeeded++;
      let extra = `kind=${stages.kind}, ${stages.layers} layer(s)`;
      if (facts['Decoys dropped']) extra += `, ${facts['Decoys dropped']} decoy(s) dropped`;
      if (staticOnly) extra += ', static-only';
      if (stages.artifacts && stages.artifacts.length > 0) extra += `, ${stages.artifacts.length} artifact(s): ${stages.artifacts.slice(0, 2).join(', ').substring(0, 100)}`;
      lines.push(`${label}. <${item.url}> — SUCCESS: \`${body.length}\` → \`${clean.length}\` bytes (${extra})`);
      if (item.depth + 1 < MAX_STAGE_DEPTH) {
        for (const s of stages.stages) {
          if (s && typeof s.url === 'string' && s.url.length <= 2000 && !seen.has(s.url)) {
            queue.push({ url: s.url, depth: item.depth + 1 });
          }
        }
      }
    }

    // ---- Auto-detect the obfuscator of what we just fetched ---------------
    // Runs on the biggest scripts only: a loader stub tells you nothing, and
    // every call is a third-party request. Opt out with LEAKD_DETECT_ON_GET=0.
    const detectFindings = [];
    const wantDetect = plainFetch
      && process.env.LEAKD_DETECT_ON_GET !== '0'
      && leakdApiKey()
      && !hasFlag(message.content, '--no-detect');
    if (wantDetect && detectCandidates.length > 0) {
      const budget = Number(process.env.LEAKD_DETECT_MAX || 3);
      const picks = [...detectCandidates].sort((a, b) => b.body.length - a.body.length).slice(0, budget);
      for (const c of picks) {
        // Skip stubs: under 2KB there is no obfuscator structure to detect.
        if (c.body.length < 2000) {
          detectFindings.push({ label: c.label, skipped: 'too small to be worth detecting (<2 KB)' });
          continue;
        }
        try {
          const r = await leakdDetect(c.body, `${c.label}.lua`);
          detectFindings.push({
            label: c.label,
            name: r.name,
            confidence: r.confidence,
            hint: suggestNextCommand(r.name),
          });
        } catch (err) {
          detectFindings.push({ label: c.label, error: err.message });
        }
      }
    }

    const keyLine = key ? `Key: \`${scrubSecrets(key).substring(0, 60)}\`` : 'Key: *(none)*';
    const color = failed === 0 ? COLORS.success : (succeeded === 0 ? COLORS.error : COLORS.warn);
    let desc = `${urls.length} URL${urls.length > 1 ? 's' : ''} — **${succeeded} succeeded, ${failed} failed** — ${keyLine}\n`;
    if (jnkieChains || jnkieFailed) {
      desc += `Jnkie delivery: ${jnkieChains} completed${jnkieFailed ? `, ${jnkieFailed} incomplete` : ''}.\n`;
    }
    if (processed > urls.length) {
      desc += `Followed the chain: ${processed} fetched, depth ${maxDepth}, ${formatBytes(totalBytes)} total`
        + (containers ? `, ${containers} protected container(s)` : '')
        + (jnkieChains ? `, ${jnkieChains} Jnkie delivery chain(s) completed` : '')
        + (jnkieFailed ? `, ${jnkieFailed} Jnkie chain(s) incomplete` : '')
        + (loadstringRuns ? `, loadstring pass ran ${loadstringRuns}x and resolved ${loadstringResolved} stage(s)` : '')
        + (escalated ? `, ${escalated} needed an escalated attempt` : '')
        + (retried ? `, ${retried} retried after a transient error` : '')
        + ` — ${Math.round((Date.now() - runStarted) / 1000)}s of the ${Math.round(RUN_BUDGET_MS / 1000)}s budget.\n`;
    }
    if (detectFindings.length > 0) {
      desc += '\n**Obfuscator detection** (LeakD)\n';
      for (const f of detectFindings) {
        if (f.error) desc += `${f.label}. detection failed: \`${scrubSecrets(f.error).substring(0, 140)}\`\n`;
        else if (f.skipped) desc += `${f.label}. not detected — ${f.skipped}\n`;
        else desc += `${f.label}. **${f.name}**${formatConfidence(f.confidence)}${f.hint ? ` — next: ${f.hint}` : ''}\n`;
      }
    }
    desc += lines.join('\n') + '\n';
    // Show the largest script, not the first: stage 1 is normally a few-hundred
    // byte loader stub, while the payload the user wants is the big one.
    const preview = (plainFetch && biggest) ? biggest : firstClean;
    const hasPreview = typeof preview === 'string' && preview.length > 0;
    if (hasPreview) {
      if (plainFetch && biggestLabel) desc += `\nPreview of the largest script (${biggestLabel}):\n`;
      desc += '\n' + codePreview('lua', preview, 1300);
    } else if (plainFetch && containers > 0) {
      desc += '\nNothing to preview: everything fetched was an encrypted container, not readable source.\n';
    } else if (plainFetch) {
      desc += '\nNothing fetched — check the URLs and try again.\n';
    } else {
      desc += '\nNo unpacked result — `loader.lua` (below) still runs in Roblox with your key.\n';
    }
    const fields = [];
    for (let i = 1; i <= counter; i++) {
      maybeAttach(files, path.join(sessionDir, `deobfuscated_${i}.luau`), `deobfuscated_${i}.luau`);
      maybeAttach(files, path.join(sessionDir, `fetched_${i}.lua`), `fetched_${i}.lua`);
      // Protected payloads are saved as .bin and must still be delivered.
      maybeAttach(files, path.join(sessionDir, `fetched_${i}.bin`), `fetched_${i}.bin`);
      // Loader body produced by the sandboxed loadstring pass.
      maybeAttach(files, path.join(sessionDir, `loadstring_${i}.luau`), `loadstring_${i}.luau`);
      try {
        const ld = path.join(sessionDir, `loadstring_${i}`);
        for (const f of fs.readdirSync(ld)) {
          if (/^layer_\d+\.lua$/.test(f)) maybeAttach(files, path.join(ld, f), `ls${i}_${f}`);
        }
        maybeAttach(files, path.join(ld, 'strings.lua'), `ls${i}_strings.lua`);
        maybeAttach(files, path.join(ld, 'unpack.log'), `ls${i}_unpack.log`);
      } catch { /* best-effort */ }
      try {
        const ud = path.join(sessionDir, `unpack_${i}`);
        for (const f of fs.readdirSync(ud)) {
          if (/^layer_\d+\.lua$/.test(f)) maybeAttach(files, path.join(ud, f), `stage${i}_${f}`);
        }
        maybeAttach(files, path.join(ud, 'devm.log'), `stage${i}_devm.log`);
        maybeAttach(files, path.join(ud, 'strings.lua'), `stage${i}_strings.lua`);
      } catch { /* best-effort */ }
    }
    maybeAttach(files, loaderPath, 'loader.lua');
    const MAX_ATTACH = 10;
    const attached = files.slice(0, MAX_ATTACH);
    const dropped = files.length - attached.length;
    fields.push({
      name: 'Files',
      value: `${attached.length} attached (results, layers, devm, strings, loader)`
        + (loadstringRuns ? `, loadstring pass ran ${loadstringRuns}x and resolved ${loadstringResolved} stage(s)` : '')
        + (dropped > 0 ? ` — **${dropped} more omitted** (Discord cap); run with fewer URLs to fit them all` : ''),
      inline: false,
    });
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({ title: F.title, description: desc, color, fields })],
    }, attached);
  }).catch((err) => {
    console.error('[prefix] session failed:', err.message);
  });
}

async function cmdGet(message) { await cmdFetchUnpack(message, 'get'); }
async function cmdGet2(message) { await cmdFetchUnpack(message, 'get2'); }
async function cmdLuarmor(message) { await cmdFetchUnpack(message, 'luarmor'); }
async function cmdJnkie(message) { await cmdFetchUnpack(message, 'jnkie'); }

// Whole-token CLI flag lookup (`--trace`, `--no-l3`, ...). A plain \b
// lookahead does NOT work here: \b needs a word/non-word boundary, and a
// space followed by '-' is non-word/non-word, so /\b--trace\b/ never fires.
function hasFlag(content, flag) {
  const re = new RegExp(`(^|\\s)${flag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\s|$)`, 'i');
  return re.test(String(content || ''));
}

// Centralize client-identity selection so direct URL loads, `.get`, and
// `.keyforgefetch` present the same identity for the same flags.
function clientProfileName(content) {
  const text = String(content || '');
  if (hasFlag(text, '--xbox')) return 'xbox';
  if (hasFlag(text, '--mac')) return 'mac';
  if (hasFlag(text, '--studio')) return 'studio';
  if (hasFlag(text, '--mobile')) return 'mobile';
  return 'win';
}

function clientProfileHeaders(profileName = 'win') {
  return { ...ROBLOX_HEADERS, ...(CLIENT_PROFILES[profileName] || CLIENT_PROFILES.win) };
}

// ---- Local tool commands (.luast / .luraph / .flowauth / .luarmorfetch) -----
// These drive the vendored deobfuscation tools in <workspace>/tools (see
// lib/tools.js). All local: no API key, no external service. `.luraph` here
// is the LOCAL Luraph v15 devirtualizer; the LeakD `/luraphv15` variant stays
// available as `.lphv15` (local) and `.luraphv15`.
// lib/tools.js drives the vendored deobfuscation tools in <workspace>/tools.
const TOOLS = require('./tools');

// Shared skeleton: resolve input (attachment / URL / code block), announce,
// run one tool under its lock, deliver the result as a file (Pastefy when it
// exceeds Discord's 8MB cap) plus a scrubbed preview.
async function runLocalTool(message, {
  tag, title, usage, tool, lockName, run, resultName, summarize,
}) {
  await withSession(message, tag, async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir);
    } catch (err) {
      await replyEmbed(message, {
        embeds: [makeEmbed({ title: `${tag} — fetch failed`, description: err.message, color: COLORS.error })],
      });
      return;
    }
    if (!src) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: `${tag} — usage`,
          description: usage + '\nAttach a `.lua`/`.luau` file, paste a `https://...` URL, or send a ```lua code block```.',
          color: COLORS.info,
        })],
      });
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: `${title} — working…`,
        description: `Source: \`${src.sourceName}\` (${fs.statSync(src.inputPath).size} bytes)\nRuns locally — this can take a few minutes on big scripts.`,
        color: COLORS.info,
      })],
    });
    let res;
    try {
      res = await TOOLS.withToolLock(lockName, () => run(src, sessionDir));
    } catch (err) {
      await editEmbed(status, {
        embeds: [makeEmbed({ title: `${title} — crashed`, description: scrubSecrets(err.message).substring(0, 400), color: COLORS.error })],
      });
      return;
    }
    if (res.prereq && !res.prereq.ok) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: `${tag} — not set up`,
          description: res.prereq.detail + `\n\nTool dir: \`${res.prereq.dir || 'n/a'}\``,
          color: COLORS.error,
        })],
      });
      return;
    }
    const outPath = res.outputPath || (res.recovered && res.recovered.path) || (res.payload && res.payload.path) || null;
    const files = [];
    let desc = '';
    let resultVerdict = null;
    if (res.ok && outPath && fs.existsSync(outPath)) {
      let body = applyWatermark(fs.readFileSync(outPath, 'utf-8'));
      // The sandbox preamble (no-op network shims, _bsdata0, the injected
      // script key) is not part of the user's script. Strip it, then judge what
      // is left: a genuine lift, only scaffolding, or an explicit failure.
      const stripped = stripHarnessScaffolding(body);
      if (stripped.droppedBlocks > 0) body = applyWatermark(stripped.text);
      resultVerdict = analyzeLocalResult(stripped.text);
      const name = resultName(src.sourceName, outPath);
      const local = path.join(sessionDir, name);
      try { fs.writeFileSync(local, body, 'utf-8'); } catch { /* keep the tool's own path */ }
      desc = `Source: \`${src.sourceName}\` → \`${body.length}\` bytes\n`;
      if (stripped.droppedBlocks > 0) {
        desc += `Removed ${stripped.droppedBlocks} block(s) of sandbox scaffolding (network shims, _bsdata0, injected key) that is not part of your script.\n`;
      }
      if (!resultVerdict.useful) {
        // Be honest: this is not a deobfuscated script.
        desc += `\n**Not a usable result.** `;
        if (resultVerdict.devirtFailed) {
          desc += 'The local devirtualizer gave up on this script (it emits an explicit `devirt:` failure rather than lifted code). '
            + 'The file below is only the harness output.\n';
        } else if (resultVerdict.scaffoldOnly) {
          desc += 'Nothing was lifted — what is left after removing the sandbox scaffolding is empty.\n';
        } else {
          desc += `Only ${resultVerdict.liftedLines} line(s) of code were recovered.\n`;
        }
        desc += 'Try `.luraph` (LeakD API), `.luast`, or `.luraphv14` for this file.\n';
      }
      maybeAttach(files, local, name);
      if (files.length === 0) {
        desc += `\nToo big for Discord — attaching a link instead.\n`;
      } else {
        desc += `File attached: \`${name}\`\n`;
      }
      try {
        const url = await publishPastefy(name, body, sessionDir);
        if (url) desc += `\nFull source: <${url}>\n`;
      } catch (err) {
        desc += `\nPastefy upload failed: \`${scrubSecrets(err.message).substring(0, 160)}\`\n`;
      }
      desc += '\n' + codePreview('lua', body, 1200);
    } else {
      desc = `**No result.** ${res.error ? scrubSecrets(res.error).substring(0, 900) : 'the tool produced no output.'}\n`;
    }
    const fields = [];
    if (summarize) {
      for (const f of summarize(res)) fields.push(f);
    }
    // Ship the tool log too — it carries the verdict, timings and diagnostics.
    if (res.log) {
      const logName = `${tag}_${Date.now()}.log`;
      const logPath = path.join(sessionDir, logName);
      try { fs.writeFileSync(logPath, res.log, 'utf-8'); } catch { /* best-effort */ }
      maybeAttach(files, logPath, logName);
    }
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({
        title: (res.ok && resultVerdict && !resultVerdict.useful) ? `${title} — nothing usable lifted` : (res.ok ? title : `${title} — failed`),
        description: desc,
        color: (res.ok && resultVerdict && !resultVerdict.useful) ? COLORS.warn : (res.ok ? COLORS.success : COLORS.error),
        fields,
      })],
    }, files.slice(0, 10));
  }).catch((err) => {
    console.error('[prefix] local tool session failed:', err.message);
  });
}

// `.luast [file|url|code]` — LUAST v1 (+ auto level-3) via luau-recover.
async function cmdLuast(message) {
  await runLocalTool(message, {
    tag: 'luast',
    title: 'LUAST — deobfuscated',
    usage: '**Usage:** `.luast` + attach a script, paste a `https://...` URL, or send a ```lua code block```.\nRecovers LUAST v1 control flow (and routes level-3 through the static emulator) locally.',
    lockName: 'luast',
    run: (src, sessionDir) => TOOLS.luast({
      inputPath: src.inputPath,
      outputPath: path.join(sessionDir, 'luast_out.luau'),
      // No \b: it needs a word/non-word boundary, and a space followed by
      // '-' is non-word/non-word, so /\b--no-l3\b/ never matches.
      l3: !hasFlag(message.content, '--no-l3'),
    }),
    resultName: (srcName) => `luast_${srcName.replace(/\.[^.]+$/, '')}.luau`,
    summarize: (res) => {
      const f = [];
      if (res.status) f.push({ name: 'Pipeline', value: `\`${res.status}\``, inline: true });
      if (res.complexity != null) f.push({ name: 'Output complexity', value: String(res.complexity), inline: true });
      return f;
    },
  });
}

// `.lphv15 [file|url|code]` — LOCAL Luraph v15 devirtualizer (no API key).
// `.luraph` below is the token-gated LeakD variant.
async function cmdLuraphLocal(message) {
  const traceOnly = hasFlag(message.content, '--trace');
  await runLocalTool(message, {
    tag: 'lphv15',
    title: 'Luraph V15 — deobfuscated (local)',
    usage: '**Usage:** `.lphv15` + attach a script, paste a `https://...` URL, or send a ```lua code block```.\n'
      + 'Local full devirtualization, no API key needed (can take minutes).\n'
      + 'Add `--trace` for a fast execution trace instead. `.luraph` is the LeakD API route; `.luraphv14` handles v14.7/14.8/14.9.',
    lockName: 'luraph',
    run: (src, sessionDir) => TOOLS.luraph({
      inputPath: src.inputPath,
      outputPath: path.join(sessionDir, 'luraph_out.luau'),
      traceOnly,
    }),
    resultName: (srcName) => `luraph_${srcName.replace(/\.[^.]+$/, '')}.luau`,
    summarize: () => (traceOnly
      ? [{ name: 'Mode', value: 'trace only (`--trace`)', inline: true }]
      : [{ name: 'Mode', value: 'full devirtualization', inline: true }]),
  });
}

// `.luraphv14 <14.7|14.8|14.9|auto>` — Luraph v14.x engines (v15's own
// frontend only knows v15). Version is auto-detected from the header unless
// forced; a header-stripped script needs the flag.
async function cmdLuraphV14(message) {
  const content = message.content;
  let engine = 'auto';
  const m = String(content).match(/(?:^|\s)(14\.7|14\.8|14\.9|v14\.7|v14\.8|v14\.9)(?=\s|$)/i);
  if (m) engine = m[1].toLowerCase().replace('v14.', '14.');
  const strict = hasFlag(content, '--strict');
  await runLocalTool(message, {
    tag: 'luraphv14',
    title: 'Luraph v14 — deobfuscated (local)',
    usage: '**Usage:** `.luraphv14` + attach a script, paste a `https://...` URL, or send a ```lua code block```.\n'
      + 'Handles Luraph **14.7 / 14.8 / 14.9**. The version is auto-detected; add `14.7`, `14.8` or `14.9` if the header was stripped and detection is wrong.\n'
      + 'Hard v14 samples often cannot be fully devirtualized — the behaviour trace is returned instead.',
    lockName: 'luraphV14',
    run: (src, sessionDir) => TOOLS.luraphV14({
      inputPath: src.inputPath,
      outputPath: path.join(sessionDir, 'luraph14_out.luau'),
      engine,
      // --strict turns off the trace fallback, so a sample that cannot be
      // devirtualized is reported as a failure instead of a thin result.
      traceFallback: !strict,
    }),
    resultName: (srcName) => `luraph14_${srcName.replace(/\.[^.]+$/, '')}.luau`,
    summarize: (res) => {
      const f = [];
      if (res.detected) f.push({ name: 'Detected', value: res.detected, inline: true });
      f.push({ name: 'Engine', value: engine === 'auto' ? 'auto' : `forced ${engine}`, inline: true });
      if (res.partial) {
        f.push({ name: 'Result', value: '**behaviour trace only** — this sample could not be fully devirtualized (common on hard v14). The trace is attached; it is not lifted source.', inline: false });
      }
      return f;
    },
  });
}

// `.ironbrew1 [file|url|code]` — Ironbrew1 devirtualizer (a modern Luau VM
// obfuscator, not the old Lua 5.1 IronBrew). The engine is always forced, so a
// renamed or stripped header cannot drop us onto a generic trace fallback.
async function cmdIronbrew1(message) {
  const traceOnly = hasFlag(message.content, '--trace');
  await runLocalTool(message, {
    tag: 'ironbrew1',
    title: 'Ironbrew1 — deobfuscated (local)',
    usage: '**Usage:** `.ironbrew1` + attach a script, paste a `https://...` URL, or send a ```lua code block```.\n'
      + 'Devirtualizes Ironbrew1-protected Luau (the `-- this file was generated using ironbrew1` header).\n'
      + 'Add `--trace` for a fast behaviour trace instead of a full lift. No API key needed.',
    lockName: 'ironbrew1',
    run: (src, sessionDir) => TOOLS.ironbrew1({
      inputPath: src.inputPath,
      outputPath: path.join(sessionDir, 'ironbrew1_out.luau'),
      traceOnly,
    }),
    resultName: (srcName) => `ironbrew1_${srcName.replace(/\.[^.]+$/, '')}.luau`,
    summarize: (res) => {
      const f = [];
      if (res.detected) f.push({ name: 'Engine', value: res.detected, inline: true });
      if (res.functionsCaptured != null) {
        f.push({
          name: 'Functions',
          value: `${res.functionsCaptured} captured${res.functionsNeverRan != null ? `, ${res.functionsNeverRan} never ran` : ''}`,
          inline: true,
        });
      }
      f.push({ name: 'Mode', value: traceOnly ? 'trace only (`--trace`)' : 'full devirtualization', inline: true });
      if (res.usedTrace && !traceOnly) {
        f.push({ name: 'Result', value: '**behaviour trace only** — the lifter fell back, so this is not fully devirtualized source.', inline: false });
      }
      return f;
    },
  });
}

// Owner gate for beta/unreleased commands. OWNER_ID is the bot owner's
// Discord user ID (see .env.example). Unset means "nobody may run it" —
// fail closed, never open.
function botOwnerId() {
  return String(process.env.OWNER_ID || '').trim();
}

function isBotOwner(message) {
  const owner = botOwnerId();
  return !!owner && String(message?.author?.id || '') === owner;
}

// `.lua [file|url|code]` — LuaMullvad obfuscation (owner-only beta).
// VM-based protection at paranoid level by default; the result is delivered by
// DM (file + Pastefy link + /raw endpoint), never in-channel, so the
// protected build stays out of the shared channel history.
async function cmdLuaObfuscate(message) {
  const owner = botOwnerId();
  if (!owner) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.lua — not configured',
        description: 'This command is owner-only (beta) and no `OWNER_ID` is set. '
          + 'Add your Discord user ID as `OWNER_ID` in `.env` to enable it.',
        color: COLORS.error,
      })],
    });
    return;
  }
  if (!isBotOwner(message)) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.lua — owner only',
        description: 'This command is in closed beta and only the bot owner may use it.',
        color: COLORS.error,
      })],
    });
    return;
  }
  const levelMatch = String(message.content).match(/(?:^|\s)--level\s+(standard|high|paranoid)(?=\s|$)/i);
  const level = levelMatch
    ? levelMatch[1].toLowerCase()
    : (hasFlag(message.content, '--standard') ? 'standard'
      : hasFlag(message.content, '--high') ? 'high' : 'paranoid');
  const seedMatch = String(message.content).match(/(?:^|\s)--seed\s+(\d+)(?=\s|$)/);
  const seed = seedMatch ? Number(seedMatch[1]) : undefined;
  const nodeMatch = String(message.content).match(/(?:^|\s)--node\s+([A-Za-z0-9_-]{1,32})(?=\s|$)/);
  const node = nodeMatch ? nodeMatch[1].toLowerCase() : undefined;
  const triFlag = (on, off) => hasFlag(message.content, on) ? true : hasFlag(message.content, off) ? false : undefined;
  // Dedicated flow (not runLocalTool): the obfuscated build is delivered by DM
  // ONLY, never in-channel, so a beta build never lands in shared history.
  await withSession(message, 'luaobf', async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir, { inlineCode: true });
    } catch (err) {
      await replyEmbed(message, {
        embeds: [makeEmbed({ title: '.lua — fetch failed', description: err.message, color: COLORS.error })],
      });
      return;
    }
    if (!src) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: '.lua — usage',
          description: '**Usage:** `.lua` + attach a script, paste a `https://...` URL, send a ```lua code block```, or type code inline (`.lua print("test")`).\n'
            + 'Obfuscates with LuaMullvad (3-tier nested VM, per-build randomized instruction set). Default level is **paranoid**; '
            + 'override with `--level standard|high|paranoid`, `--seed N`, `--antitamper/--no-antitamper`, `--at-stealth/--no-at-stealth`, `--at-special/--no-at-special`, `--virtualize/--no-virtualize`, `--vm-compress/--no-vm-compress`, `--cff/--no-cff`, `--env-fork/--no-env-fork`, `--hardcode-globals/--no-hardcode-globals`, `--genesis/--no-genesis`, `--node lightcore` (LightCore bundle), `--vm-antianalysis/--no-vm-antianalysis`. The result is DM’d to you with the file, a Pastefy link, and a `/raw` endpoint.\n'
            + 'Owner-only while in beta.',
          color: COLORS.info,
        })],
      });
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: 'LuaMullvad — obfuscating…',
        description: `Source: \`${src.sourceName}\` (${fs.statSync(src.inputPath).size} bytes)\nLevel: \`${level}\` · VM build — check your DMs when it lands.`,
        color: COLORS.info,
      })],
    });
    let res;
    try {
      res = await TOOLS.withToolLock('luamullvad', () => TOOLS.luamullvad({
        inputPath: src.inputPath,
        outputPath: path.join(sessionDir, 'luamullvad_out.luau'),
        level,
        seed,
        antitamper: triFlag('--antitamper', '--no-antitamper'),
        atStealth: triFlag('--at-stealth', '--no-at-stealth'),
        atSpecial: triFlag('--at-special', '--no-at-special'),
        virtualize: triFlag('--virtualize', '--no-virtualize'),
        vmCompress: triFlag('--vm-compress', '--no-vm-compress'),
        cff: triFlag('--cff', '--no-cff'),
        envFork: triFlag('--env-fork', '--no-env-fork'),
        hardcodeGlobals: triFlag('--hardcode-globals', '--no-hardcode-globals'),
        genesis: triFlag('--genesis', '--no-genesis'),
        node,
        vmAntianalysis: triFlag('--vm-antianalysis', '--no-vm-antianalysis'),
      }));
    } catch (err) {
      await editEmbed(status, {
        embeds: [makeEmbed({ title: 'LuaMullvad — crashed', description: scrubSecrets(err.message).substring(0, 400), color: COLORS.error })],
      });
      return;
    }
    if (res.prereq && !res.prereq.ok) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: '.lua — not set up',
          description: res.prereq.detail + `\n\nTool dir: \`${res.prereq.dir || 'n/a'}\``,
          color: COLORS.error,
        })],
      });
      return;
    }
    if (!res.ok || !res.outputPath || !fs.existsSync(res.outputPath)) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: 'LuaMullvad — failed',
          description: `**No result.** ${res.error ? scrubSecrets(res.error).substring(0, 900) : 'the tool produced no output.'}\n`,
          color: COLORS.error,
        })],
      });
      return;
    }
    const body = fs.readFileSync(res.outputPath, 'utf-8');
    const name = `luamullvad_${src.sourceName.replace(/\.[^.]+$/, '')}.luau`;
    const local = path.join(sessionDir, name);
    try { fs.writeFileSync(local, body, 'utf-8'); } catch { /* keep the tool's own path */ }
    // Ship the tool log too.
    const files = [];
    if (res.log) {
      const logPath = path.join(sessionDir, `luaobf_${Date.now()}.log`);
      try { fs.writeFileSync(logPath, res.log, 'utf-8'); } catch { /* best-effort */ }
    }
    maybeAttach(files, local, name);
    let pasteUrl = null;
    let rawUrl = null;
    try {
      const url = await publishPastefy(name, body, sessionDir);
      if (url) {
        pasteUrl = url;
        rawUrl = pasteRawUrl(url);
      }
    } catch (err) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: 'LuaMullvad — obfuscated, paste failed',
          description: `Build succeeded (\`${body.length}\` bytes) but Pastefy upload failed: \`${scrubSecrets(err.message).substring(0, 160)}\`. Delivering by DM with the file.`,
          color: COLORS.warn,
        })],
      });
    }
    // DM the owner: file + Pastefy link + /raw endpoint. Nothing sensitive
    // stays in the channel — the channel reply is only a pointer.
    let dmOk = false;
    let dmErr = null;
    try {
      const user = await message.client.users.fetch(owner);
      const lines = [
        `Your \`.lua\` obfuscation is done — \`${src.sourceName}\` → \`${body.length}\` bytes (VM · level \`${res.level || level}\`).`,
      ];
      if (pasteUrl) lines.push(`Pastefy: <${pasteUrl}>`);
      if (rawUrl) lines.push(`Raw endpoint: <${rawUrl}>`);
      if (res.wroteLine) lines.push(`Build: \`${res.wroteLine.substring(0, 120)}\``);
      await user.send({
        embeds: [makeEmbed({
          title: 'LuaMullvad — obfuscated build',
          description: lines.join('\n'),
          color: COLORS.success,
        })],
        files: files.slice(0, 3),
      });
      dmOk = true;
    } catch (err) {
      dmErr = err;
    }
    if (dmOk) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: 'LuaMullvad — obfuscated',
          description: `Done — \`${body.length}\` bytes at level \`${res.level || level}\`. **Check your DMs** for the file, Pastefy link, and \`/raw\` endpoint.`,
          color: COLORS.success,
        })],
      });
    } else {
      // DMs closed or fetch failed: fall back to in-channel delivery so the
      // owner's build is not lost. Owner-only command, so no leak.
      const fields = [];
      if (pasteUrl) fields.push({ name: 'Pastefy', value: `<${pasteUrl}>`, inline: false });
      if (rawUrl) fields.push({ name: 'Raw endpoint', value: `<${rawUrl}>`, inline: false });
      await editEmbedWithFiles(status, message, {
        embeds: [makeEmbed({
          title: 'LuaMullvad — obfuscated (DMs closed, delivering here)',
          description: `Could not DM you (${dmErr ? scrubSecrets(dmErr.message).substring(0, 120) : 'unknown error'}) — delivering in-channel instead.\n\`${src.sourceName}\` → \`${body.length}\` bytes (VM · level \`${res.level || level}\`).`,
          color: COLORS.warn,
          fields,
        })],
      }, files.slice(0, 3));
    }
  }).catch((err) => {
    console.error('[prefix] luaobf session failed:', err.message);
  });
}

// KeyForge serves an executor guard INSTEAD of the payload when the request
// looks like a browser: a ~345-byte stub that only `error()`s. The plaintext
// string is the cheapest reliable way to tell "I got the real script" from
// "I got told to go away", and getting that backwards is the whole failure mode
// of fetching these, so it is checked on every response.
const KEYFORGE_GUARD_RE = /must be run from a Roblox executor/i;

// Fingerprints for "which protector is this", so a fetch can say something
// useful without lifting anything. Cheap string scan only.
const PROTECTOR_FINGERPRINTS = [
  ['Luraph', /\bLPH_|Luraph Obfuscator|this file was encrypted by Luraph/i],
  ['Ironbrew1', /generated using ironbrew1/i],
  ['MoonSec', /moonsec|\$KEY\$|\$ENDING\$/i],
  ['IronBrew (Lua 5.1)', /IronBrew is a obfuscator/i],
];

// `.keyforgefetch <loader-url>` — fetch an executor-hosted loader payload with
// the identity those hosts expect, then say what came back. Does not attempt to
// lift or devirtualize anything.
async function cmdKeyforgeFetch(message) {
  const url = (message.content.match(/https?:\/\/\S+/) || [])[0];
  if (!url) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.keyforgefetch — usage',
        description: '**Usage:** `.keyforgefetch <loader-url>`\n'
          + 'Fetches an executor-hosted loader (KeyForge and similar) using the client identity those '
          + 'hosts expect, then runs the **LeakD detector** over it to name the protector.\n'
          + 'Flags: `--xbox` `--mac` `--studio` `--mobile` (default: Windows client)',
        color: COLORS.info,
      })],
    });
    return;
  }
  const profileName = clientProfileName(message.content);
  const headers = clientProfileHeaders(profileName);
  await withSession(message, 'keyforgefetch', async (sessionDir) => {
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.keyforgefetch — working…',
        description: `Fetching \`${url.substring(0, 180)}\`\nIdentity: \`${CLIENT_PROFILES[profileName]['User-Agent']}\``,
        color: COLORS.info,
      })],
    });
    let body;
    try {
      body = await fetchUrlSafe(url, { timeoutMs: 60000, maxBytes: MAX_SOURCE_BYTES, headers });
    } catch (err) {
      await editEmbed(status, {
        embeds: [makeEmbed({ title: '.keyforgefetch — failed', description: `Fetch failed: ${err.message}`, color: COLORS.error })],
      });
      return;
    }
    const text = Buffer.isBuffer(body) ? body.toString('utf-8') : String(body == null ? '' : body);
    const bytes = Buffer.byteLength(text, 'utf-8');
    // The guard is a real 200 with a real body, so nothing but this check
    // distinguishes it from a successful fetch.
    if (KEYFORGE_GUARD_RE.test(text)) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: '.keyforgefetch — executor guard, not the payload',
          description: `The host answered with a **${bytes}-byte guard stub** instead of the script.\n\n`
            + 'That stub is a genuine HTTP 200, so a plain fetch looks like it worked. It means the '
            + 'request did not look like the client this host expects — sending browser headers '
            + '(`Sec-Fetch-*`, `Sec-CH-UA*`) or a browser User-Agent triggers it.\n\n'
            + `Tried: \`${CLIENT_PROFILES[profileName]['User-Agent']}\`. Try another identity with `
            + '`--xbox`, `--mac`, `--studio` or `--mobile`.',
          color: COLORS.warn,
        })],
      });
      return;
    }
    if (!text.trim()) {
      await editEmbed(status, {
        embeds: [makeEmbed({ title: '.keyforgefetch — empty', description: `The host returned an empty body (${bytes} bytes).`, color: COLORS.error })],
      });
      return;
    }
    const verdict = classifyBody(text);
    // Local fingerprints first: free, instant, and they catch the headers of
    // protectors we have an engine for. LeakD is asked next because it is the
    // only thing that can name a protector we have no engine for.
    const local = PROTECTOR_FINGERPRINTS.find(([, re]) => re.test(text));
    let slug = 'payload';
    try {
      const seg = new URL(url).pathname.split('/').filter(Boolean).pop();
      if (seg && /^[A-Za-z0-9_-]{4,64}$/.test(seg)) slug = sanitizeFilename(seg);
    } catch { /* keep the default name */ }
    const outPath = path.join(sessionDir, `${slug}.lua`);
    fs.writeFileSync(outPath, text, 'utf-8');
    // A 600KB+ payload over the wire is slow and often refused, so show what
    // came back while the detector runs rather than blocking on it.
    await editEmbed(status, {
      embeds: [makeEmbed({
        title: '.keyforgefetch — identifying…',
        description: `Fetched \`${bytes.toLocaleString()}\` bytes from \`${slug}\` as \`${CLIENT_PROFILES[profileName]['User-Agent']}\`.\nRunning the LeakD detector…`,
        color: COLORS.info,
      })],
    });
    let detected = null;
    let detectError = null;
    if (!leakdApiKey()) {
      detectError = 'LeakD API not configured — set `LEAKD_API_KEY` in `.env`.';
    } else {
      try {
        detected = await leakdDetect(text, `${slug}.lua`);
      } catch (err) {
        detectError = err.message;
      }
    }
    const fields = [
      { name: 'Size', value: `${bytes.toLocaleString()} bytes`, inline: true },
      { name: 'Lines', value: String(text.split('\n').length), inline: true },
      { name: 'Protector', value: detected ? scrubSecrets(detected.name).substring(0, 100)
        : (local ? local[0] : 'none recognised'), inline: true },
      { name: 'Confidence', value: detected && detected.confidence != null ? String(detected.confidence) : '—', inline: true },
      { name: 'Body', value: verdict.ok ? `valid (${verdict.kind}, score ${verdict.score})` : `unrecognised — ${verdict.kind}`, inline: true },
    ];
    const endpoint = detected ? mapDetectorToEndpoint(detected.name) : null;
    let desc = `Fetched \`${bytes.toLocaleString()}\` bytes from \`${slug}\` as \`${CLIENT_PROFILES[profileName]['User-Agent']}\`.\n\n`;
    if (detected) {
      const conf = detected.confidence != null ? ` (confidence \`${detected.confidence}\`)` : '';
      desc += `**${scrubSecrets(detected.name).substring(0, 120)}**${conf}\n`;
      if (endpoint) desc += `Suggested: \`.deobfuscate\` (routes to \`${endpoint}\`)\n`;
      else desc += `_No LeakD endpoint matches this one — supported: ${supportedEndpointList()}._\n`;
      desc += '_The detector lags new obfuscators per LeakD docs — treat low-confidence results as hints._\n';
      if (local && local[0] !== detected.name) {
        desc += `Local fingerprint said \`${local[0]}\` — LeakD's answer wins when they disagree.\n`;
      }
    } else if (local) {
      desc += `Local fingerprint: **${local[0]}**\n`;
      desc += detectError ? `${detectError}\n` : '';
    } else {
      desc += `No protector recognised.${detectError ? ' ' + detectError : ''}\n`;
      desc += 'Unknown to both the local fingerprints and LeakD — likely a private or custom protector.\n';
    }
    desc += '\nThis command fetches and identifies only — it does not lift or devirtualize anything.\n';
    desc += `\nFirst 400 chars:\n${codePreview('lua', text, 400)}`;
    const files = [];
    maybeAttach(files, outPath, `${slug}.lua`);
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({ title: '.keyforgefetch — fetched', description: desc, color: COLORS.success, fields })],
    }, files);
  }).catch((err) => {
    console.error('[prefix] keyforgefetch session failed:', err.message);
  });
}

// `.flowauth <loader-url>` — FlowAuth v3 one-process live chain.
async function cmdFlowAuth(message) {
  const urls = extractUrls(message.content).slice(0, 3);
  if (urls.length === 0) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.flowauth — usage',
        description: '**Usage:** `.flowauth <flowauth-loader-url>`\nRuns the FlowAuth v3 chain locally and attaches the recovered payload.\nEach `launch_ticket` is single-use, so a fresh loader is fetched on every run — only scripts you have access to.',
        color: COLORS.info,
      })],
    });
    return;
  }
  const st = TOOLS.status('flowauth');
  if (!st.ok) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.flowauth — not set up',
        description: st.detail + `\n\nTool dir: \`${st.dir}\``,
        color: COLORS.error,
      })],
    });
    return;
  }
  const status = await replyEmbed(message, {
    embeds: [makeEmbed({
      title: 'FlowAuth — working…',
      description: `Fetching the FlowAuth chain for ${urls.length} loader URL(s)…\nEach run fetches a fresh loader (tickets are single-use).`,
      color: COLORS.info,
    })],
  });
  await withSession(message, 'flowauth', async (sessionDir) => {
    const files = [];
    const lines = [];
    let firstPayload = null;
    for (const [i, url] of urls.entries()) {
      const outDir = path.join(sessionDir, `flow_${i + 1}`);
      fs.mkdirSync(outDir, { recursive: true });
      const res = await TOOLS.withToolLock('flowauth', () => TOOLS.flowauth({ loaderUrl: url, outDir }));
      if (!res.ok) {
        lines.push(`${i + 1}. <${url}> — FAILED: ${scrubSecrets(res.error || 'no payload').substring(0, 500)}`);
        continue;
      }
      if (!firstPayload && res.payload) {
        firstPayload = fs.readFileSync(res.payload.path, 'utf-8');
      }
      const name = `flowauth_${i + 1}_${res.payload.name}`;
      const local = path.join(sessionDir, name);
      try { fs.copyFileSync(res.payload.path, local); } catch { /* fall back below */ }
      maybeAttach(files, local, name);
      lines.push(`${i + 1}. <${url}> — SUCCESS: \`${res.payload.bytes}\` bytes (\`${res.payload.name}\`)`);
    }
    const ok = firstPayload !== null;
    let desc = `${urls.length} loader URL(s) — ${lines.filter((l) => l.includes('SUCCESS')).length} recovered\n`;
    desc += lines.join('\n') + '\n';
    if (ok) desc += '\n' + codePreview('lua', firstPayload, 1200);
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({
        title: ok ? 'FlowAuth — payload recovered' : 'FlowAuth — no payload',
        description: desc,
        color: ok ? COLORS.success : COLORS.error,
      })],
    }, files.slice(0, 10));
  }).catch((err) => {
    console.error('[prefix] flowauth session failed:', err.message);
  });
}

// `.luarmorfetch <loader-url> [key]` — Luarmor v4 live bootstrap chain.
// `.luarmorprobe <file|url>` — static client analysis, no key, no sandbox.
async function cmdLuarmorFetch(message) {
  const { urls, key } = parseGetArgs(message.content);
  if (urls.length === 0) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.luarmorfetch — usage',
        description: '**Usage:** `.luarmorfetch <luarmor-loader-url> [key]`\nRuns the Luarmor v4 bootstrap chain locally (loader → init → handshake → session) and attaches the recovered client.\nThe key must be yours — the session response is bound to it.',
        color: COLORS.info,
      })],
    });
    return;
  }
  const lrm = TOOLS.status('luarmorFetch');
  if (!lrm.ok) {
    await replyEmbed(message, {
      embeds: [makeEmbed({
        title: '.luarmorfetch — not set up',
        description: lrm.detail + `\n\nTool dir: \`${lrm.dir}\``,
        color: COLORS.error,
      })],
    });
    return;
  }
  const status = await replyEmbed(message, {
    embeds: [makeEmbed({
      title: 'Luarmor fetch — working…',
      description: `Running the bootstrap chain for ${urls.length} URL(s)${key ? ' with your key' : ' (no key — the chain will soft-fail)'}`,
      color: COLORS.info,
    })],
  });
  await withSession(message, 'luarmorfetch', async (sessionDir) => {
    const files = [];
    const lines = [];
    let firstRecovered = null;
    for (const [i, url] of urls.entries()) {
      const outDir = path.join(sessionDir, `lrm_${i + 1}`);
      fs.mkdirSync(outDir, { recursive: true });
      const res = await TOOLS.withToolLock('luarmorFetch', () =>
        TOOLS.luarmorFetch({ loaderUrl: url, scriptKey: key || '', outDir }));
      if (!res.ok) {
        lines.push(`${i + 1}. <${url}> — FAILED: ${scrubSecrets(res.error || 'no client recovered').substring(0, 500)}`);
        continue;
      }
      if (!firstRecovered) firstRecovered = fs.readFileSync(res.recovered.path, 'utf-8');
      const name = res.recovered.name;
      const local = path.join(sessionDir, name);
      try { fs.copyFileSync(res.recovered.path, local); } catch { /* fall back below */ }
      maybeAttach(files, local, name);
      lines.push(`${i + 1}. <${url}> — SUCCESS: \`${res.recovered.bytes}\` bytes (\`${name}\`)`);
    }
    const ok = firstRecovered !== null;
    let desc = `${urls.length} URL(s) — ${lines.filter((l) => l.includes('SUCCESS')).length} recovered\n`;
    desc += lines.join('\n') + '\n';
    if (ok) {
      desc += 'The recovered client is usually a further obfuscated layer — run it back through `.luarmor` or `.luraph`.\n\n';
      desc += codePreview('lua', firstRecovered, 1200);
    }
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({
        title: ok ? 'Luarmor fetch — client recovered' : 'Luarmor fetch — no client',
        description: desc,
        color: ok ? COLORS.success : COLORS.error,
      })],
    }, files.slice(0, 10));
  }).catch((err) => {
    console.error('[prefix] luarmorfetch session failed:', err.message);
  });
}

async function cmdLuarmorProbe(message) {
  await withSession(message, 'lrmprobe', async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir);
    } catch (err) {
      await replyEmbed(message, {
        embeds: [makeEmbed({ title: '.luarmorprobe — fetch failed', description: err.message, color: COLORS.error })],
      });
      return;
    }
    if (!src) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: '.luarmorprobe — usage',
          description: '**Usage:** `.luarmorprobe` + attach a script, paste a URL, or send a ```lua code block```.\nStatic Luarmor client analysis (signatures, loader/payload split, IOC scan). No key, no sandbox.',
          color: COLORS.info,
        })],
      });
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({ title: 'Luarmor probe — working…', description: `Source: \`${src.sourceName}\``, color: COLORS.info })],
    });
    const splitDir = path.join(sessionDir, 'split');
    fs.mkdirSync(splitDir, { recursive: true });
    const res = await TOOLS.withToolLock('luarmorProbe', () =>
      TOOLS.luarmorProbe({ inputPath: src.inputPath, outDir: splitDir, json: true }));
    const r = res.report || {};
    const fields = [
      { name: 'Luarmor client', value: r.luarmor_client ? '**yes**' : 'no', inline: true },
      { name: 'Confidence', value: String(r.confidence != null ? r.confidence.toFixed(2) : 'n/a'), inline: true },
      { name: 'Signatures', value: (r.signature_hits && r.signature_hits.length) ? r.signature_hits.join(', ').substring(0, 900) : '—', inline: false },
    ];
    const files = [];
    for (const a of res.artifacts) {
      maybeAttach(files, a.path, `probe_${a.name}`);
    }
    const desc = `Source: \`${src.sourceName}\` — ${res.isLuarmor ? '**Luarmor client detected.**' : 'Not a Luarmor client.'}\n${res.isLuarmor && files.length ? 'Loader/payload split attached below.' : ''}\n\n` + codePreview('text', res.log, 900);
    await editEmbedWithFiles(status, message, {
      embeds: [makeEmbed({
        title: 'Luarmor probe — report',
        description: desc,
        color: res.isLuarmor ? COLORS.success : COLORS.warn,
        fields,
      })],
    }, files.slice(0, 6));
  }).catch((err) => {
    console.error('[prefix] luarmorprobe session failed:', err.message);
  });
}

// ---- .luraph — Luraph V15 via LeakD API (key-gated) -----------------------
// Thin wrapper over the shared LeakD client, forced to `/luraphv15`
// (no auto-detect). Same delivery guarantees as .deobfuscate.
async function cmdLuraph(message) {
  const sendErr = (text) => replyEmbed(message, {
    embeds: [makeEmbed({ title: '.luraph — error', description: text, color: COLORS.error })],
  });
  await withSession(message, 'luraph', async (sessionDir) => {
    let src;
    try {
      src = await collectSource(message, sessionDir);
    } catch (err) {
      await sendErr(`Fetch failed: ${err.message}`);
      return;
    }
    if (!src) {
      await replyEmbed(message, {
        embeds: [makeEmbed({
          title: '.luraph — usage',
          description: 'Attach a `.lua`/`.luau`/`.txt` file, paste a `https://...` URL, or send a ```lua code block```.',
          color: COLORS.info,
        })],
      });
      return;
    }
    const sourceCode = fs.readFileSync(src.inputPath, 'utf-8');
    if (!leakdApiKey()) {
      await sendErr('LeakD API not configured — set `LEAKD_API_KEY` in `.env` (get a key at https://discord.gg/AwGHNh7Z7T).');
      return;
    }
    const status = await replyEmbed(message, {
      embeds: [makeEmbed({
        title: 'Deobfuscating…',
        description: `Source: \`${src.sourceName}\` — LeakD \`/luraphv15\``,
        color: COLORS.info,
      })],
    });
    let data;
    try {
      data = await leakdPostFile('/luraphv15', sourceCode, src.sourceName);
    } catch (err) {
      await editEmbed(status, {
        embeds: [makeEmbed({ title: '.luraph — failed', description: err.message, color: COLORS.error })],
      });
      return;
    }
    const result = leakdResultCode(data);
    // Guaranteed delivery: the RESULT always arrives as a file, never just
    // a chat preview. Empty results are reported, oversize ones (>8MB
    // Discord cap) go to Pastefy with the head shown inline.
    if (!result || result.length === 0) {
      await editEmbed(status, {
        embeds: [makeEmbed({
          title: '.luraph — empty result',
          description: `The API returned an empty result for \`${src.sourceName}\` — nothing to attach.`,
          color: COLORS.warn,
        })],
      });
      return;
    }
    const outName = `luraph_${src.sourceName.replace(/\.[^.]+$/, '')}.luau`;
    const outPath = path.join(sessionDir, outName);
    const marked = applyWatermark(result);
    fs.writeFileSync(outPath, marked, 'utf-8');
    let desc = `Source: \`${src.sourceName}\` — Result: \`${marked.length}\` bytes\n\n` + codePreview('lua', marked, 1300);
    const files = [];
    maybeAttach(files, outPath, outName);
    if (files.length === 0) {
      desc += `\nToo big for Discord — attaching a link instead.\n`;
    } else {
      desc += `\nFile attached: \`${outName}\`\n`;
    }
    try {
      const pasteUrl = await publishPastefy(outName, marked, sessionDir);
      if (pasteUrl) desc += `\nFull source: <${pasteUrl}>\n`;
    } catch (err) {
      desc += `\nPastefy upload failed: \`${scrubSecrets(err.message).substring(0, 160)}\`\n`;
    }
    await editEmbed(status, {
      embeds: [makeEmbed({
        title: 'Luraph V15 — deobfuscated',
        description: desc,
        color: COLORS.success,
        fields: [{ name: 'Bytes in/out', value: `${sourceCode.length} → ${result.length}`, inline: true }],
      })],
      files,
    });
  }).catch((err) => {
    console.error('[prefix] session failed:', err.message);
  });
}

// ---- .help — command list --------------------------------------------------
const HELP_FIELDS = [
  { name: '.l', value: 'Trace with Nita V1.1 → `recovered.lua` + Pastefy link. Takes attachment, URL, or ```code```.' },
  { name: '.l2', value: 'v1 dump + replay recorder + `events.jsonl`.' },
  { name: '.deobfuscate', value: 'LeakD API: auto-detects the obfuscator, or you pick: `.deobfuscate psu` (+ file/URL/code). `.deobfuscate list` shows all 13.' },
  { name: '.detect', value: 'LeakD `/detect`: report obfuscator name + confidence + suggested endpoint. Same inputs as `.deobfuscate`.' },
  { name: '.get2', value: '`.get` plus the Jnkie delivery chain: POSTs your key to the loader\'s delivery API and fetches the CDN payload.' },
  { name: '.get', value: 'Fetch loader URL(s) and follow the chain — no unpacking. 3 escalating attempts per URL (normal → deep → final). `<url> [key]`.' },
  { name: '.luarmor', value: 'Fetch Luarmor URL(s), unpack locally, follow next stages.' },
  { name: '.jnkie', value: 'Fetch Junkie URL(s), unpack locally, follow next stages.' },
  { name: '.luarmorfetch', value: 'Luarmor v4 bootstrap chain → recovered client, locally. `<url> [key]`.' },
  { name: '.luarmorprobe', value: 'Static Luarmor client analysis: signatures + loader/payload split. No key.' },
  { name: '.flowauth', value: 'FlowAuth v3 chain → recovered payload, locally. `<loader-url>`.' },
  { name: '.luast', value: 'LUAST v1 + level-3 recovery, locally. Attach a file/URL/code.' },
  { name: '.lphv15', value: 'Luraph v15 devirtualization, **locally** (alias `.luraphv15`). `--trace` for a fast trace. No API key.' },
  { name: '.luraph', value: 'Luraph v15 via the **LeakD API** (needs `LEAKD_API_KEY`, alias `.luraphapi`). Result always delivered as a file.' },
  { name: '.luraphv14', value: 'Luraph **14.7 / 14.8 / 14.9** devirtualization, locally. Auto-detects; add `14.7`/`14.8`/`14.9` if the header was stripped.' },
  { name: '.ironbrew1', value: 'Ironbrew1 devirtualization, locally (alias `.ib1`). `--trace` for a fast trace. No API key.' },
  { name: '.keyforgefetch', value: 'Fetch an executor-hosted loader payload (KeyForge and similar) with the identity the host expects, then identify the protector with the LeakD detector. Fetch only — no lifting.' },
  { name: '.lua', value: 'LuaMullvad obfuscation, locally (VM · default **paranoid**). **Owner-only beta.** Result DM’d to you: file + Pastefy link + `/raw` endpoint.' },
];

const HELP_EXAMPLES =
  '`.l https://example.com/script.lua`\n' +
  '`.deobfuscate` + attach `script.lua`\n' +
  '`.detect` + attach `script.lua`\n' +
  '`.luast` + attach `script.lua`\n' +
  '`.get https://api.luarmor.net/files/v3/loaders/xxxx.lua mykey123`';

async function cmdHelp(message) {
  await replyEmbed(message, {
    embeds: [makeEmbed({
      title: 'Nita Bot — commands',
      description: 'This channel only. Every reply scrubs secrets before sending.\n\nExamples:\n' + HELP_EXAMPLES,
      color: COLORS.info,
      fields: HELP_FIELDS,
    })],
  });
}

// Entry point for index.js messageCreate. Returns true if handled.
async function handlePrefixMessage(message) {
  if (!message || message.author?.bot) return false;
  if (!isAllowedChannel(message.channelId)) return false;
  const token = String(message.content || '').split(/\s+/)[0].toLowerCase();
  if (token === '.help') { await cmdHelp(message); return true; }
  if (token === '.l2') { await cmdNita(message, true); return true; }
  if (token === '.l') { await cmdNita(message, false); return true; }
  if (token === '.deobfuscate') { await cmdDeobfuscate(message); return true; }
  if (token === '.detect') { await cmdDetect(message); return true; }
  if (token === '.get') { await cmdGet(message); return true; }
  if (token === '.get2') { await cmdGet2(message); return true; }
  if (token === '.luarmor') { await cmdLuarmor(message); return true; }
  if (token === '.jnkie') { await cmdJnkie(message); return true; }
  if (token === '.luast') { await cmdLuast(message); return true; }
  if (token === '.flowauth') { await cmdFlowAuth(message); return true; }
  if (token === '.luarmorfetch') { await cmdLuarmorFetch(message); return true; }
  if (token === '.luarmorprobe') { await cmdLuarmorProbe(message); return true; }
  // `.luraph` is the LeakD API; the local devirtualizer is `.lphv15`.
  if (token === '.luraph' || token === '.luraphapi') { await cmdLuraph(message); return true; }
  if (token === '.lphv15' || token === '.luraphv15') { await cmdLuraphLocal(message); return true; }
  if (token === '.luraphv14' || token === '.luraph14') { await cmdLuraphV14(message); return true; }
  if (token === '.ironbrew1' || token === '.ib1') { await cmdIronbrew1(message); return true; }
  if (token === '.keyforgefetch' || token === '.kffetch') { await cmdKeyforgeFetch(message); return true; }
  if (token === '.lua') { await cmdLuaObfuscate(message); return true; }
  return false;
}

module.exports = {
  handlePrefixMessage,
  isAllowedChannel,
  ALLOWED_CHANNEL_ID,
  ALLOWED_CHANNEL_IDS,
  LUNE_BIN,
  NITA_V1,
  NITA_V2,
  extractUrls,
  extractInlineCode,
  parseGetArgs,
  buildLoaderSource,
  parseDeobfuscateHint,
  leakdBaseUrl,
  leakdApiKey,
  mapDetectorToEndpoint,
  deobfuscatorChoiceList,
  leakdPostFile,
  leakdDetect,
  leakdResultCode,
  LEAKD_ENDPOINTS,
  TOOLS,
  applyWatermark,
  WATERMARK_NAME,
  harvestStageUrls,
  scriptLikeUrl,
  identifyExecutor,
  classifyBody,
  fetchEscalating,
  ESCALATION_TIERS,
  valFlag,
  clampInt,
  stripHarnessScaffolding,
  looksLikeScaffoldOnly,
  analyzeLocalResult,
  fetchJnkieDelivery,
  JNKIE_DELIVERY_RE,
  formatBytes,
  formatConfidence,
  suggestNextCommand,
  runLune,
  luneTimeoutMs,
  sanitizeLuneEnv,
  safePathSegment,
  clientProfileName,
  clientProfileHeaders,
  orderedProfiles,
  buildWatermarkedSource,
  isBoilerplateOnly,
  dormantWhy,
  botOwnerId,
  isBotOwner,
  uploadPastefy,
  uploadFilebin,
  publishPastefy,
  pasteRawUrl,
};
