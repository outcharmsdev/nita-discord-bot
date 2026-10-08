// Daily changelog poster.
//
// Posts a digest of what changed — improvements, additions, fixes, removals —
// to a Discord webhook once a day. Because this workspace is not a git repo
// there is no diff to derive from, so changes are recorded explicitly as
// entries in changelog/entries.jsonl (see addEntry) and rendered here.
//
//   node src/lib/changelog.js --dry-run     print today's digest, post nothing
//   node src/lib/changelog.js --now         post immediately (ignores the timer)
//   node src/lib/changelog.js --days 7      include the last 7 days
//
// Config (.env):
//   CHANGELOG_WEBHOOK_URL  the webhook to post to. Unset -> disabled, and the
//                          timer never fires. This is a SECRET: anyone holding
//                          it can post as the bot, so it never goes in git.
//   CHANGELOG_ENABLED      1 (default when a URL is set) / 0 to disable
//   CHANGELOG_INTERVAL_MS  default 24h
//   CHANGELOG_EMBED        1 to send an embed (default), 0 for plain text
const fs = require('fs');
const path = require('path');
const https = require('https');

const HERE = __dirname;
// Standalone runs (`node src/lib/changelog.js …`) do not go through
// src/index.js, which is what loads .env for the bot process. Load it here too
// or CHANGELOG_WEBHOOK_URL is invisible no matter what .env says.
try {
  // eslint-disable-next-line global-require
  require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });
} catch { /* dotenv absent: rely on the real environment */ }
const WORKSPACE = path.join(HERE, '..', '..', '..');
const ENTRIES_FILE = path.join(WORKSPACE, 'changelog', 'entries.jsonl');
const STATE_FILE = path.join(WORKSPACE, 'changelog', 'state.json');

const INTERVAL_MS = Number(process.env.CHANGELOG_INTERVAL_MS || 24 * 60 * 60 * 1000);

// ---- Entry storage ---------------------------------------------------------
// JSONL so concurrent writers never corrupt the file and a crash mid-append
// costs at most one line. Schema per line:
//   { "ts": ISO, "kind": "added|improved|fixed|removed|note", "what": "..." }
const VALID_KINDS = ['added', 'improved', 'fixed', 'removed', 'note'];

function ensureDir(p) {
  try { fs.mkdirSync(path.dirname(p), { recursive: true }); } catch { /* exists */ }
}

function readEntries() {
  let raw;
  try { raw = fs.readFileSync(ENTRIES_FILE, 'utf-8'); } catch { return []; }
  const out = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const e = JSON.parse(t);
      if (e && typeof e.what === 'string' && e.what.trim()) out.push(e);
    } catch { /* skip a torn line rather than fail the whole digest */ }
  }
  return out;
}

function addEntry(kind, what, when = new Date()) {
  if (!VALID_KINDS.includes(kind)) throw new Error(`unknown kind "${kind}" (use: ${VALID_KINDS.join(', ')})`);
  const text = String(what || '').trim();
  if (!text) throw new Error('entry text is empty');
  ensureDir(ENTRIES_FILE);
  const entry = { ts: (when instanceof Date ? when : new Date(when)).toISOString(), kind, what: text };
  fs.appendFileSync(ENTRIES_FILE, JSON.stringify(entry) + '\n', 'utf-8');
  return entry;
}

// ---- Rendering -------------------------------------------------------------
const KIND_LABEL = {
  added: 'Added',
  improved: 'Improved',
  fixed: 'Fixed',
  removed: 'Removed',
  note: 'Note',
};
const KIND_ICON = { added: '\u{1F195}', improved: '\u{1F4A1}', fixed: '\u{1F41B}', removed: '\u{1F5D1}', note: '\u{1F4DD}' };
const ORDER = ['added', 'improved', 'fixed', 'removed', 'note'];

function todayKey(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

// Entries from the last `days` calendar days (UTC), oldest first.
function recentEntries(days = 1) {
  const cutoff = new Date(Date.now() - (days - 1) * 24 * 60 * 60 * 1000);
  cutoff.setUTCHours(0, 0, 0, 0);
  return readEntries()
    .filter((e) => new Date(e.ts) >= cutoff)
    .sort((a, b) => new Date(a.ts) - new Date(b.ts));
}

function renderPlain(entries, days) {
  const lines = [];
  lines.push(`**Nita Bot — daily changelog** (${days === 1 ? todayKey() : `last ${days} days`})`);
  lines.push('');
  let any = false;
  for (const kind of ORDER) {
    const group = entries.filter((e) => e.kind === kind);
    if (!group.length) continue;
    any = true;
    lines.push(`**${KIND_LABEL[kind]}**`);
    for (const e of group) lines.push(`${KIND_ICON[kind]} ${e.what}`);
    lines.push('');
  }
  if (!any) lines.push('No changes recorded for this window.');
  return lines.join('\n').slice(0, 1900);
}

function renderEmbed(entries, days) {
  const colors = { added: 0x57F287, improved: 0x5865F2, fixed: 0xFEE75C, removed: 0xED4245, note: 0x9BA5B4 };
  const total = entries.length;
  const fields = [];
  for (const kind of ORDER) {
    const group = entries.filter((e) => e.kind === kind);
    if (!group.length) continue;
    // Discord caps a field value at 1024 chars, so chunk instead of slicing
    // (which used to cut sentences in half and lose whole entries).
    let chunk = [];
    let chunkLen = 0;
    const flush = () => {
      if (!chunk.length) return;
      fields.push({
        name: `${KIND_ICON[kind]} ${KIND_LABEL[kind]} (${group.length})`,
        value: chunk.join('\n'),
        inline: false,
      });
      chunk = [];
      chunkLen = 0;
    };
    for (const e of group) {
      const line = `• ${e.what}`;
      // +2 for the newline join, leave headroom under Discord's 1024.
      if (chunkLen + line.length + 2 > 1000) flush();
      chunk.push(line);
      chunkLen += line.length + 2;
    }
    flush();
  }
  const counts = ORDER
    .map((k) => `${KIND_LABEL[k]} ${entries.filter((e) => e.kind === k).length}`)
    .filter((s) => !s.endsWith(' 0'))
    .join(' · ');
  return {
    title: `Daily changelog — ${days === 1 ? todayKey() : `last ${days} days`}`,
    description: total
      ? `${total} change${total === 1 ? '' : 's'}${counts ? `\n${counts}` : ''}`
      : 'No changes recorded for this window.',
    color: colors[entries.length ? entries[entries.length - 1].kind : 'note'],
    fields,
    footer: { text: 'Nita Bot · local Luau pipeline' },
    timestamp: new Date().toISOString(),
  };
}

// ---- Delivery --------------------------------------------------------------
function webhookUrl() {
  return String(process.env.CHANGELOG_WEBHOOK_URL || '').trim();
}

function enabled() {
  if (process.env.CHANGELOG_ENABLED === '0') return false;
  return webhookUrl().length > 0;
}

// Already-posted watermark so a restart does not re-send the same day.
function readState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')); } catch { return { lastPosted: null }; }
}
function writeState(s) {
  ensureDir(STATE_FILE);
  fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2), 'utf-8');
}

// Webhook URLs are always https://discord.com/api/webhooks/<id>/<token>.
function postToWebhook(url, payload) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch { reject(new Error('malformed CHANGELOG_WEBHOOK_URL')); return; }
    if (parsed.protocol !== 'https:') { reject(new Error('webhook URL must be https')); return; }
    // Discord by default. CHANGELOG_WEBHOOK_ALLOW_HOST exists so delivery can
    // be pointed at a self-hosted proxy or a mock during testing; setting it
    // weakens the guarantee that only Discord receives the payload.
    const allow = String(process.env.CHANGELOG_WEBHOOK_ALLOW_HOST || 'discord.com,discordapp.com')
      .split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
    if (!allow.includes(parsed.hostname.toLowerCase())) {
      reject(new Error(`refusing to post to a non-Discord host: ${parsed.hostname}`
        + ' (set CHANGELOG_WEBHOOK_ALLOW_HOST to override)'));
      return;
    }
    const body = Buffer.from(JSON.stringify(payload), 'utf-8');
    const req = https.request({
      method: 'POST',
      hostname: parsed.hostname,
      // Respect an explicit port; omitting it silently dials 443 and only works
      // for Discord's default endpoint.
      port: parsed.port ? Number(parsed.port) : 443,
      path: parsed.pathname + parsed.search,
      headers: { 'Content-Type': 'application/json', 'Content-Length': body.length },
      timeout: 30000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf-8');
        if (res.statusCode >= 200 && res.statusCode < 300) { resolve({ ok: true, status: res.statusCode }); return; }
        reject(new Error(`webhook HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('webhook timed out')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function sendDigest({ days = 1, force = false, log = console.log } = {}) {
  const url = webhookUrl();
  if (!url) {
    log('[changelog] CHANGELOG_WEBHOOK_URL is not set — nothing posted (set it in .env to enable).');
    return { ok: false, skipped: true };
  }
  const state = readState();
  const stamp = todayKey();
  if (!force && state.lastPosted === stamp) {
    log(`[changelog] already posted for ${stamp} — skipping.`);
    return { ok: true, skipped: true };
  }
  const entries = recentEntries(days);
  const useEmbed = process.env.CHANGELOG_EMBED !== '0';
  // `username` is a top-level webhook field, not an embed property.
  const payload = useEmbed
    ? { username: process.env.CHANGELOG_USERNAME || 'Nita Bot Changelog', embeds: [renderEmbed(entries, days)] }
    : { username: process.env.CHANGELOG_USERNAME || 'Nita Bot Changelog', content: renderPlain(entries, days) };

  try {
    await postToWebhook(url, payload);
  } catch (err) {
    // 429 means we are being rate limited: leave the watermark alone so the
    // next tick retries instead of silently skipping a day.
    log(`[changelog] post failed: ${err.message}`);
    return { ok: false, error: err.message };
  }
  state.lastPosted = stamp;
  state.lastPostedAt = new Date().toISOString();
  writeState(state);
  log(`[changelog] posted ${entries.length} change(s) for ${stamp}.`);
  return { ok: true, posted: entries.length };
}

// Fire once per interval. Started by src/index.js after the client is ready so
// a failed post never blocks login.
function startDailyTimer({ intervalMs = INTERVAL_MS, log = console.log } = {}) {
  if (!enabled()) {
    log('[changelog] disabled (no CHANGELOG_WEBHOOK_URL or CHANGELOG_ENABLED=0).');
    return null;
  }
  // Small initial delay: post after the gateway is up, not during boot.
  const timer = setInterval(() => {
    sendDigest({ log }).catch(() => { /* sendDigest logs its own errors */ });
  }, intervalMs);
  if (timer.unref) timer.unref();
  log(`[changelog] daily poster armed (every ${Math.round(intervalMs / 60000)} min).`);
  return timer;
}

module.exports = {
  addEntry,
  readEntries,
  recentEntries,
  renderPlain,
  renderEmbed,
  sendDigest,
  startDailyTimer,
  enabled,
  webhookUrl,
  ENTRIES_FILE,
  STATE_FILE,
  VALID_KINDS,
};

// ---- CLI -------------------------------------------------------------------
if (require.main === module) {
  const argv = process.argv.slice(2);
  const has = (f) => argv.includes(f);
  const val = (f, d) => {
    const i = argv.indexOf(f);
    return i !== -1 && argv[i + 1] ? argv[i + 1] : d;
  };
  const days = Number(val('--days', has('--today') ? 1 : 1)) || 1;
  // Track whether an action ran, so the usage banner is not printed alongside
  // an in-flight --now post.
  let handled = false;

  if (has('--dry-run')) {
    handled = true;
    const entries = recentEntries(days);
    if (process.env.CHANGELOG_EMBED === '0') console.log(renderPlain(entries, days));
    else console.log(JSON.stringify(renderEmbed(entries, days), null, 2));
    console.error(`\n[changelog] dry run — ${entries.length} entr(ies) in window, nothing posted.`);
    process.exit(0);
  }
  if (has('--now')) {
    handled = true;
    // --now respects the same-day guard so a second run cannot double-post;
    // add --force to post again deliberately.
    sendDigest({ days, force: has('--force') })
      .then((r) => process.exit(r.ok ? 0 : 1));
  } else if (has('--add')) {
    handled = true;
    try {
      const e = addEntry(val('--kind', 'improved'), val('--what', ''));
      console.log('[changelog] recorded:', JSON.stringify(e));
      process.exit(0);
    } catch (err) {
      console.error('[changelog] ' + err.message);
      process.exit(1);
    }
  }
  if (!handled) {
    console.log('usage: node src/lib/changelog.js [--dry-run|--now [--force]|--add --kind K --what TEXT] [--days N]');
  }
}