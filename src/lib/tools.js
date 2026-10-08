// Local runner for the vendored the vendored deobfuscation tools.
//
//   tools/Luast                     python  luau-recover   (LUAST v1 + L3)
//   tools/Deobfuscator-Luraph-V15   node    deob.js        (Luraph v15 devirt)
//   tools/Luarmor-Fetch             python  main.py        (Luarmor v4 chain)
//   tools/FlowAuth-Deobfuscator     python  flowauth_two_phase.py (FlowAuth v3)
//
// Everything runs locally — no API key, no external service. Paths are
// overridable with TOOLS_DIR / LURAPH_REPO / LUARMOR_FETCH_REPO /
// FLOWAUTH_REPO / LUAST_REPO, and the Luau binary with LUAU_BIN.
//
// Serialization: Luarmor-Fetch and FlowAuth write into a FIXED `work/`
// directory inside their repo, so two concurrent runs would clobber each
// other. Every tool therefore goes through withToolLock(name, fn) — one run
// per tool at a time, queued rather than raced.
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// <workspace>/tools — this file lives in <workspace>/discord-bot/src/lib/.
const WORKSPACE = path.join(__dirname, '..', '..', '..');
const TOOLS_DIR = process.env.TOOLS_DIR || path.join(WORKSPACE, 'tools');

const DIRS = {
  luraph: process.env.LURAPH_REPO || path.join(TOOLS_DIR, 'Deobfuscator-Luraph-V15'),
  luarmorFetch: process.env.LUARMOR_FETCH_REPO || path.join(TOOLS_DIR, 'Luarmor-Fetch'),
  flowauth: process.env.FLOWAUTH_REPO || path.join(TOOLS_DIR, 'FlowAuth-Deobfuscator'),
  luast: process.env.LUAST_REPO || path.join(TOOLS_DIR, 'Luast'),
  // Luraph v14.7 / v14.8 / v14.9 engines (a separate frontend from v15).
  luraphV14: process.env.LURAPH_V14_REPO || path.join(TOOLS_DIR, 'luraph-v15-v14.x-deobfuscator'),
  // Ironbrew1 lives in the same repo but behind the plugin frontend (deob.py).
  ironbrew1: process.env.IRONBREW1_REPO || process.env.LURAPH_V14_REPO || path.join(TOOLS_DIR, 'luraph-v15-v14.x-deobfuscator'),
  // LuaMullvad obfuscator (lives at workspace root, not under tools/).
  luamullvad: process.env.LUAMULLVAD_REPO || path.join(WORKSPACE, 'luamullvad'),
};

const PYTHON = process.env.PYTHON_BIN || 'python3';

// Hard ceiling per run. Luraph on a 1.6MB script takes ~12 min upstream, so
// these are generous; the embed is edited with the failure either way.
const TIMEOUTS = {
  luraph: Number(process.env.TOOL_TIMEOUT_LURAPH_MS || 12 * 60 * 1000),
  luast: Number(process.env.TOOL_TIMEOUT_LUAST_MS || 8 * 60 * 1000),
  luarmorFetch: Number(process.env.TOOL_TIMEOUT_LUARMOR_MS || 10 * 60 * 1000),
  flowauth: Number(process.env.TOOL_TIMEOUT_FLOWAUTH_MS || 10 * 60 * 1000),
  luamullvad: Number(process.env.TOOL_TIMEOUT_LUAMULLVAD_MS || 10 * 60 * 1000),
  probe: 60 * 1000,
};

function exists(p) {
  try { return fs.existsSync(p); } catch { return false; }
}

function isFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

// The patched Luau CLI. Stock builds freeze the vector metatable, so
// `v.Magnitude` dies inside nita.luau — build it with build_luau.py.
function luauBin() {
  if (process.env.LUAU_BIN) return process.env.LUAU_BIN;
  const exe = process.platform === 'win32' ? 'luau.exe' : 'luau';
  const bundled = path.join(DIRS.luraph, 'bin', exe);
  return isFile(bundled) ? bundled : exe;
}

// Luau/FlowAuth/Luarmor-Fetch all need the same sandbox repo; require the
// two files that qualify it so a partial copy fails fast and legibly.
function sandboxOk(dir) {
  return isFile(path.join(dir, 'core', 'harness.py')) && isFile(path.join(dir, 'runtime', 'nita.luau'));
}

// Availability for one tool: { ok, detail, ... }. `detail` is written for
// humans and shown verbatim in the embed, so it names the fix.
function status(name) {
  const dir = DIRS[name];
  if (!dir) return { ok: false, detail: 'unknown tool' };
  switch (name) {
    case 'luast':
      if (!isDir(dir) || !isFile(path.join(dir, 'deobfuscate.py'))) {
        return { ok: false, dir, detail: `Luast is not installed at \`${dir}\` (set LUAST_REPO or TOOLS_DIR).` };
      }
      return { ok: true, dir, detail: 'ready' };
    case 'luraph':
      if (!isDir(dir) || !isFile(path.join(dir, 'deob.js'))) {
        return { ok: false, dir, detail: `Luraph V15 is not installed at \`${dir}\` (set LURAPH_REPO or TOOLS_DIR).` };
      }
      if (!isFile(path.join(dir, 'bin', 'luau')) && !isFile(path.join(dir, 'bin', 'luau.exe')) && !process.env.LUAU_BIN) {
        return { ok: false, dir, detail: 'no `bin/luau` — build the patched runtime with `python build_luau.py` (needs git, cmake, a C++ compiler).' };
      }
      return { ok: true, dir, detail: 'ready' };
    case 'luarmorFetch':
      if (!isDir(dir) || !isFile(path.join(dir, 'main.py'))) {
        return { ok: false, dir, detail: `Luarmor fetcher is not installed at \`${dir}\` (set LUARMOR_FETCH_REPO or TOOLS_DIR).` };
      }
      if (!sandboxOk(DIRS.luraph)) {
        return { ok: false, dir, detail: 'needs the shared Luau sandbox (core/harness.py + runtime/nita.luau under LURAPH_REPO).' };
      }
      return { ok: true, dir, detail: 'ready' };
    case 'flowauth':
      if (!isDir(dir) || !isFile(path.join(dir, 'flowauth_crack', 'flowauth_two_phase.py'))) {
        return { ok: false, dir, detail: `FlowAuth fetcher is not installed at \`${dir}\` (set FLOWAUTH_REPO or TOOLS_DIR).` };
      }
      if (!sandboxOk(DIRS.luraph)) {
        return { ok: false, dir, detail: 'needs the shared Luau sandbox (core/harness.py + runtime/nita.luau under LURAPH_REPO).' };
      }
      return { ok: true, dir, detail: 'ready' };
    case 'luraphV14': {
      const deobf = path.join(dir, 'Deobfuscator', 'deobf');
      if (!isFile(path.join(deobf, 'cli.py'))) {
        return { ok: false, dir: deobf, detail: `Luraph v14.x frontend not found at \`${deobf}\` (set LURAPH_V14_REPO or TOOLS_DIR).` };
      }
      // This repo ships Windows binaries only; on Linux it would fall back to
      // a stock `luau` from PATH, which freezes the vector metatable and kills
      // every run. Demand the patched Linux build be installed in its bin/.
      const bin = path.join(deobf, 'bin');
      const missing = ['luau', 'luau-ast'].filter((b) => !isFile(path.join(bin, b)));
      if (missing.length > 0) {
        return {
          ok: false,
          dir: bin,
          detail: `missing patched Linux binary/binar${missing.length > 1 ? 'ies' : 'y'}: ${missing.join(', ')}. `
            + `Copy them from the v15 repo (stock Luau freezes the vector metatable): `
            + `cp Deobfuscator-Luraph-V15/bin/luau Deobfuscator-Luraph-V15/bin/luau-ast ${bin}/`,
        };
      }
      return { ok: true, dir: deobf, detail: 'ready' };
    }
    case 'ironbrew1': {
      // Same deobf/ tree as the v14 frontend; different entry point.
      const deobf = path.join(dir, 'Deobfuscator', 'deobf');
      if (!isFile(path.join(deobf, 'deob.py'))) {
        return { ok: false, dir: deobf, detail: `Ironbrew1 frontend not found at \`${deobf}\` (set IRONBREW1_REPO or TOOLS_DIR).` };
      }
      const bin = path.join(deobf, 'bin');
      const missing = ['luau', 'luau-ast'].filter((b) => !isFile(path.join(bin, b)));
      if (missing.length > 0) {
        return {
          ok: false,
          dir: bin,
          detail: `missing patched Linux binary/binar${missing.length > 1 ? 'ies' : 'y'}: ${missing.join(', ')}. `
            + 'Stock Luau freezes the vector metatable, so every devirtualization run dies.',
        };
      }
      return { ok: true, dir: deobf, detail: 'ready' };
    }
    case 'luamullvad': {
      // Standalone Lua CLI (lua 5.1+). Needs the `lua` binary plus the full
      // src/ tree; demand both so a partial copy fails fast and legibly.
      if (!isDir(dir) || !isFile(path.join(dir, 'luamullvad.lua'))) {
        return { ok: false, dir, detail: `LuaMullvad not found at \`${dir}\` (set LUAMULLVAD_REPO).` };
      }
      const required = ['lexer', 'parser', 'compiler', 'vmemit', 'obfuscate'];
      const missingSrc = required.filter((m) => !isFile(path.join(dir, 'src', `${m}.lua`)));
      if (missingSrc.length > 0) {
        return { ok: false, dir, detail: `LuaMullvad src/ is incomplete (missing: ${missingSrc.join(', ')}).` };
      }
      return { ok: true, dir, detail: 'ready' };
    }
    default:
      return { ok: false, detail: 'unknown tool' };
  }
}

function allStatus() {
  const out = {};
  for (const name of ['luast', 'luraph', 'luraphV14', 'ironbrew1', 'luarmorFetch', 'flowauth', 'luamullvad']) out[name] = status(name);
  return out;
}

// ---- run helpers ------------------------------------------------------------

// The vendored tools print an attribution banner on every run; drop it so it
// never reaches Discord in attached logs or error lines.
function stripBanner(text) {
  return String(text || '')
    .split('\n')
    .filter((l) => !/^\s*\[[^\]]*\]\s*(Luarmor|FlowAuth)\s+fetcher\s*--/i.test(l)
      && !/\bTool by\b/i.test(l)
      && !/^\s*\[[^\]]*\]\s*Luarmor fetcher\s*--/i.test(l))
    .join('\n');
}

// execFile with timeout + capped buffer. Never rejects: a failed run is data
// (the tool prints its diagnosis to stderr, and we forward it).
function exec(cmd, args, { cwd, timeoutMs = TIMEOUTS.luraph, env = {} } = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, {
      cwd,
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, PYTHONUNBUFFERED: '1', ...env },
    }, (err, stdout, stderr) => {
      const out = String(stdout || '');
      const errOut = String(stderr || '');
      let code = 0;
      if (err) {
        if (typeof err.code === 'number') code = err.code;
        else if (err.killed) code = -1;              // timeout kill
        else code = 1;
      }
      resolve({
        ok: code === 0,
        code,
        timedOut: !!(err && err.killed),
        stdout: out,
        stderr: errOut,
        // Both streams, capped — tools interleave their progress lines.
        log: stripBanner(out + (out.endsWith('\n') || !out ? '' : '\n') + errOut).slice(-8000),
      });
    });
  });
}

// One run per tool at a time; the rest queue. `waited` reports whether the
// caller had to wait, so the embed can say "queued behind another run".
const locks = new Map();
function withToolLock(name, fn) {
  const prev = locks.get(name) || Promise.resolve();
  let release;
  const next = new Promise((r) => { release = r; });
  locks.set(name, prev.then(() => next));
  const waited = locks.get(name) !== prev;
  return prev.then(() => fn({ waited })).finally(() => {
    release();
    if (locks.get(name) === next) locks.delete(name);
  });
}

// Newest-first artifact listing under `dir`, so the embed can show what the
// run produced without hardcoding each tool's filename scheme.
function listArtifacts(dir, { limit = 12, maxBytes = 8 * 1024 * 1024 } = {}) {
  const out = [];
  const walk = (d, depth) => {
    if (depth > 2 || out.length >= limit * 3) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p, depth + 1); continue; }
      let st;
      try { st = fs.statSync(p); } catch { continue; }
      if (st.size <= 0 || st.size > maxBytes) continue;
      out.push({ path: p, name: e.name, bytes: st.size, mtime: st.mtimeMs });
    }
  };
  walk(dir, 0);
  return out.sort((a, b) => b.mtime - a.mtime).slice(0, limit);
}

// Files present before the run, so a re-run of the same command doesn't
// re-attach last time's leftovers as if they were new.
function snapshot(dir) {
  const seen = new Set();
  try {
    for (const a of listArtifacts(dir, { limit: 200 })) seen.add(a.path);
  } catch { /* ignore */ }
  return seen;
}

function newArtifacts(dir, before, limit = 12) {
  return listArtifacts(dir, { limit }).filter((a) => !before.has(a.path));
}

// ---- tool entry points ------------------------------------------------------

// LUAST v1 (+ level-3 auto-route). Input is a local file; output is `-o`.
// `--report` makes it print a JSON summary we can show as fields.
async function luast({ inputPath, outputPath, timeoutMs, l3 = false }) {
  const st = status('luast');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  const before = snapshot(path.dirname(outputPath));
  const args = [path.join(st.dir, 'deobfuscate.py'), inputPath, '-o', outputPath, '--report'];
  if (!l3) args.push('--no-l3');
  const res = await exec(PYTHON, args, { cwd: st.dir, timeoutMs: timeoutMs || TIMEOUTS.luast });
  let report = null;
  const jsonStart = res.stdout.indexOf('[\n  {');
  if (jsonStart !== -1) {
    try { report = JSON.parse(res.stdout.slice(jsonStart)); } catch { report = null; }
  }
  const wrote = isFile(outputPath) && fs.statSync(outputPath).size > 0;
  const entry = report && Array.isArray(report) ? report[0] : null;
  return {
    ok: res.ok && wrote,
    wrote,
    outputPath,
    report,
    // The generic pipeline reports `valid_output`; only the level-3 router
    // sets an explicit `status` (ok-l3), so fall back to it.
    status: (entry && (entry.status || (entry.valid_output ? 'ok' : 'fallback'))) || (wrote ? 'ok' : null),
    complexity: entry && entry.output_complexity,
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    artifacts: newArtifacts(st.dir, before),
    error: !wrote ? (res.timedOut ? `timed out after ${Math.round((timeoutMs || TIMEOUTS.luast) / 1000)}s` : (res.log.slice(-800) || 'no output written')) : null,
  };
}

// Luraph v15 devirtualization via deob.js. traceOnly skips bytecode lifting
// (seconds instead of minutes) and still emits the execution trace.
async function luraph({ inputPath, outputPath, timeoutMs, traceOnly = false, budgetSec = 30 }) {
  const st = status('luraph');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  const before = snapshot(path.dirname(outputPath));
  const args = [path.join(st.dir, 'deob.js'), inputPath, '-o', outputPath,
    '--timeout', String(Math.max(30, Math.round((timeoutMs || TIMEOUTS.luraph) / 1000))),
    '--budget', String(budgetSec)];
  if (traceOnly) args.push('--no-devirt');
  const res = await exec('node', args, { cwd: st.dir, timeoutMs: (timeoutMs || TIMEOUTS.luraph) + 15000, env: { PYTHON_BIN: PYTHON } });
  let wrote = false;
  try { wrote = isFile(outputPath) && fs.statSync(outputPath).size > 0; } catch { wrote = false; }
  // deob.js exits 0 even when a file failed, so judge on the artifact.
  return {
    ok: wrote,
    wrote,
    outputPath,
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    artifacts: newArtifacts(path.dirname(outputPath), before),
    error: wrote ? null : (res.timedOut ? 'timed out — raise TOOL_TIMEOUT_LURAPH_MS for large scripts' : (res.log.slice(-1200) || 'no output written')),
  };
}

// Static Luarmor client analysis: signatures, loader/payload split, IOC scan.
// Pure Python — no sandbox, no key, safe to run on anything.
async function luarmorProbe({ inputPath, outDir, json = false }) {
  const dir = DIRS.luarmorFetch;
  if (!isDir(dir) || !isFile(path.join(dir, 'main.py'))) {
    return { ok: false, error: `Luarmor fetcher is not installed at \`${dir}\` (set LUARMOR_FETCH_REPO or TOOLS_DIR).` };
  }
  const args = [path.join(dir, 'main.py'), 'probe', inputPath];
  if (json) args.push('--json');
  if (outDir) args.push('--split', outDir);
  const res = await exec(PYTHON, args, { cwd: dir, timeoutMs: TIMEOUTS.probe });
  let parsed = null;
  if (json) {
    const i = res.stdout.indexOf('{');
    if (i !== -1) {
      try { parsed = JSON.parse(res.stdout.slice(i)); } catch { parsed = null; }
    }
  }
  return {
    ok: res.ok,
    // probe exits 2 for "not a Luarmor client" — a verdict, not a crash.
    isLuarmor: !!(parsed && parsed.luarmor_client),
    report: parsed,
    log: res.log,
    exitCode: res.code,
    artifacts: outDir ? listArtifacts(outDir, { limit: 6 }) : [],
    error: res.code === 2 ? 'not a Luarmor client (exit 2)' : (res.ok ? null : res.log.slice(-800)),
  };
}

// Luarmor v4 bootstrap chain: loader -> sephal init -> handshake -> session.
// Needs a real script_key; without one the chain soft-fails by design.
//
// The sephal init (stage 2) sits behind a CDN gate that fingerprints the
// User-Agent: `Roblox/Win32` — the UA Luarmor-Fetch hardcodes — gets a
// 327-byte "executor is not supported" trap, while `Roblox/WinInet` gets the
// real ~760KB bootstrapper. We fetch the init ourselves with the WinInet UA
// and hand it over via --init, so the chain works without an executor cache.
const LUAU_INIT_URL = process.env.LUARMOR_INIT_URL || 'https://cdn.luarmor.net/v4_init_sephal.lua';
const LUAU_UA = 'Roblox/WinInet';
// The tool rejects an init under 100000 bytes or containing its trap marker,
// so anything smaller than this is a placeholder, not the real stage 2.
const MIN_INIT_BYTES = 100000;

function fetchInit(outDir) {
  return new Promise((resolve) => {
    execFile('curl', ['-s', '-L', '--max-time', '60', '-A', LUAU_UA, '-o', path.join(outDir, 'init_sephal.lua'),
      '-w', '%{http_code}', LUAU_INIT_URL], { timeout: 70000, maxBuffer: 1024 }, (err, stdout) => {
      const dest = path.join(outDir, 'init_sephal.lua');
      const code = String(stdout || '').trim();
      let size = 0;
      try { size = fs.statSync(dest).size; } catch { /* no file */ }
      if (err || code !== '200' || size < MIN_INIT_BYTES) {
        let note = `init fetch failed (HTTP ${code || 'n/a'}, ${size} bytes)`;
        try {
          const head = fs.readFileSync(dest, 'utf-8').slice(0, 200);
          if (/executor is not supported/i.test(head)) note += ' — the CDN served its executor trap';
        } catch { /* unreadable */ }
        resolve({ ok: false, detail: note });
        return;
      }
      resolve({ ok: true, path: dest, bytes: size });
    });
  });
}

async function luarmorFetch({ loaderUrl, scriptKey, initPath, outDir, timeoutMs }) {
  const st = status('luarmorFetch');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  fs.mkdirSync(outDir, { recursive: true });
  const before = snapshot(outDir);
  let init = initPath && isFile(initPath) ? { ok: true, path: initPath, bytes: fs.statSync(initPath).size, source: 'supplied' } : null;
  if (!init) {
    // No --init from the caller: fetch stage 2 ourselves with the UA the CDN
    // gate actually accepts, rather than letting the tool hit the trap.
    init = await fetchInit(outDir);
    if (init.ok) init.source = 'cdn';
  }
  if (!init.ok) {
    return {
      ok: false,
      error: `${init.detail}. The real sephal init is executor-only; save one from an executor cache (static_content_170926/init-<module>.lua) and pass its path.`,
      artifacts: [],
      log: '',
      exitCode: 1,
    };
  }
  const args = [path.join(st.dir, 'main.py'), 'two-phase',
    '--loader-url', loaderUrl,
    '--repo', DIRS.luraph,
    '--luau', luauBin(),
    '--init', init.path,
    '--output', outDir];
  if (scriptKey) args.push('--script-key', scriptKey);
  const res = await exec(PYTHON, args, {
    cwd: st.dir,
    timeoutMs: timeoutMs || TIMEOUTS.luarmorFetch,
    env: scriptKey ? { LRM_SCRIPT_KEY: scriptKey } : {},
  });
  const arts = newArtifacts(outDir, before);
  const recovered = arts.find((a) => /^recovered_.*\.lua$/.test(a.name));
  return {
    ok: !!recovered,
    recovered,
    artifacts: arts,
    initBytes: init.bytes,
    initSource: init.source,
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    error: recovered ? null : (res.timedOut ? 'timed out — raise TOOL_TIMEOUT_LUARMOR_MS' : (res.log.slice(-1500) || 'no recovered client produced')),
  };
}

// FlowAuth v3 chain: launch_ticket is SINGLE-USE, so every run fetches a
// fresh loader; the payload lands in flowauth_crack/work/.
async function flowauth({ loaderUrl, timeoutMs, outDir }) {
  const st = status('flowauth');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  const workDir = path.join(st.dir, 'flowauth_crack', 'work');
  fs.mkdirSync(workDir, { recursive: true });
  const before = snapshot(workDir);
  const res = await exec(PYTHON, [
    path.join(st.dir, 'flowauth_crack', 'flowauth_two_phase.py'),
    '--loader-url', loaderUrl,
    '--repo', DIRS.luraph,
  ], {
    cwd: path.join(st.dir, 'flowauth_crack'),
    timeoutMs: timeoutMs || TIMEOUTS.flowauth,
  });
  const arts = newArtifacts(workDir, before);
  const payload = arts.find((a) => /\.payload\.lua$/.test(a.name)) || arts.find((a) => a.name === 'payload_source.lua');
  if (payload && outDir) {
    try {
      fs.copyFileSync(payload.path, path.join(outDir, payload.name));
    } catch { /* attachment falls back to the repo path */ }
  }
  return {
    ok: !!payload,
    payload,
    artifacts: arts,
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    error: payload ? null : (res.timedOut ? 'timed out — raise TOOL_TIMEOUT_FLOWAUTH_MS' : (res.log.slice(-1500) || 'no payload produced')),
  };
}

// Luraph v14.7 / v14.8 / v14.9 via the v14 frontend (cli.py). `engine` forces a
// version when the header was stripped; otherwise auto-detection runs.
// `traceFallback` mirrors the tool's own flag: when full devirtualization
// yields nothing it returns the behaviour trace instead of failing, which is
// what it does for most hard v14 samples.
async function luraphV14({ inputPath, outputPath, engine = 'auto', traceFallback = true, timeoutMs, budgetSec = 30 }) {
  const st = status('luraphV14');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  const before = snapshot(path.dirname(outputPath));
  const budget = Number(process.env.TOOL_TIMEOUT_LURAPH14_MS || 10 * 60 * 1000);
  const limit = timeoutMs || budget;
  const args = [
    path.join(st.dir, 'cli.py'), inputPath, '-o', outputPath,
    '--timeout', String(Math.max(30, Math.round(limit / 1000) - 15)),
    '--budget', String(budgetSec),
  ];
  if (engine && engine !== 'auto') args.push('--engine', engine);
  if (traceFallback) args.push('--trace-fallback');
  const res = await exec(PYTHON, args, { cwd: st.dir, timeoutMs: limit + 20000 });
  let wrote = false;
  try { wrote = isFile(outputPath) && fs.statSync(outputPath).size > 0; } catch { wrote = false; }

  // cli.py raises (and writes nothing) when devirt produces nothing and
  // --trace-fallback is absent, so exit status alone is not the verdict.
  const usedTrace = /returning behaviour trace/i.test(res.log);
  const detected = (res.log.match(/\[\*\]\s*engine:\s*([^\n]+)/i) || [])[1] || null;
  return {
    ok: wrote,
    wrote,
    outputPath,
    detected: detected ? detected.trim() : null,
    usedTrace,
    // A behaviour trace is not lifted source; the caller should say so.
    partial: usedTrace,
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    artifacts: newArtifacts(path.dirname(outputPath), before),
    error: wrote ? null : (res.timedOut
      ? 'timed out — raise TOOL_TIMEOUT_LURAPH14_MS for large scripts'
      : (res.log.slice(-1400) || 'no output written')),
  };
}

// Ironbrew1 devirtualization via the plugin frontend (deob.py).
// `--engine` is not meaningful here: the plugin registry picks the engine from
// `--obfuscator`, and we always force ironbrew1 so a mis-detection cannot
// silently run the generic fallback. `traceOnly` returns the behaviour trace
// instead of lifted code (seconds rather than minutes).
async function ironbrew1({ inputPath, outputPath, timeoutMs, traceOnly = false, budgetSec = 30 }) {
  const st = status('ironbrew1');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  const before = snapshot(path.dirname(outputPath));
  const limit = Number(process.env.TOOL_TIMEOUT_IRONBREW1_MS || 10 * 60 * 1000);
  const budget = timeoutMs || limit;
  const args = [
    path.join(st.dir, 'deob.py'), inputPath, '-o', outputPath,
    // Force the plugin: detection is bypassed so a weak/renamed header cannot
    // drop us onto the generic trace-only fallback.
    '--obfuscator', 'ironbrew1',
    '--timeout', String(Math.max(30, Math.round(budget / 1000) - 15)),
    '--budget', String(budgetSec),
  ];
  if (traceOnly) args.push('--no-devirt');
  const res = await exec(PYTHON, args, { cwd: st.dir, timeoutMs: budget + 20000 });
  let wrote = false;
  try { wrote = isFile(outputPath) && fs.statSync(outputPath).size > 0; } catch { wrote = false; }
  const detected = (res.log.match(/\[*]\s*obfuscator:\s*([^\n]+)/i) || [])[1] || null;
  const captured = (res.log.match(/(\d+) functions captured \((\d+) never ran\)/i) || []);
  return {
    ok: wrote,
    wrote,
    outputPath,
    detected: detected ? detected.trim() : null,
    // The upstream trace fallback prints this when it could not devirtualize.
    usedTrace: traceOnly || /behaviour trace|trace only|not devirtualized/i.test(res.log),
    functionsCaptured: captured[1] ? Number(captured[1]) : null,
    functionsNeverRan: captured[2] ? Number(captured[2]) : null,
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    artifacts: newArtifacts(path.dirname(outputPath), before),
    error: wrote ? null : (res.timedOut
      ? 'timed out — raise TOOL_TIMEOUT_IRONBREW1_MS for large scripts'
      : (res.log.slice(-1400) || 'no output written')),
  };
}

// LuaMullvad obfuscator via the standalone Lua CLI.
// The driver resolves src/ from arg[0] and accepts --seed N plus the
// --antitamper/--at-stealth/--vm-antianalysis toggles, so the input path can
// be absolute and every option is forwarded verbatim.
// `level` is one of standard|high|paranoid (default paranoid).
async function luamullvad({ inputPath, outputPath, level = 'paranoid', node, seed, antitamper, atStealth, atSpecial, virtualize, vmCompress, cff, envFork, hardcodeGlobals, genesis, vmAntianalysis, timeoutMs }) {
  const st = status('luamullvad');
  if (!st.ok) return { ok: false, error: st.detail, prereq: st };
  const lvl = ['standard', 'high', 'paranoid'].includes(String(level).toLowerCase())
    ? String(level).toLowerCase()
    : 'paranoid';
  const before = snapshot(path.dirname(outputPath));
  const limit = timeoutMs || TIMEOUTS.luamullvad;
  const cliArgs = ['luamullvad.lua', inputPath, outputPath, '--level', lvl];
  if (node !== undefined && node !== null && String(node).trim() !== '') {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(String(node))) return { ok: false, error: 'invalid node name — use `lightcore`.' };
    cliArgs.push('--node', String(node));
  }
  if (seed !== undefined && seed !== null && String(seed).trim() !== '') {
    const n = Number(seed);
    if (!Number.isInteger(n)) return { ok: false, error: `invalid seed \`${String(seed).substring(0, 40)}\` — use an integer.` };
    cliArgs.push('--seed', String(n));
  }
  if (antitamper === true) cliArgs.push('--antitamper');
  else if (antitamper === false) cliArgs.push('--no-antitamper');
  if (atStealth === true) cliArgs.push('--at-stealth');
  else if (atStealth === false) cliArgs.push('--no-at-stealth');
  if (atSpecial === true) cliArgs.push('--at-special');
  else if (atSpecial === false) cliArgs.push('--no-at-special');
  if (virtualize === true) cliArgs.push('--virtualize');
  else if (virtualize === false) cliArgs.push('--no-virtualize');
  if (vmCompress === true) cliArgs.push('--vm-compress');
  else if (vmCompress === false) cliArgs.push('--no-vm-compress');
  if (cff === true) cliArgs.push('--cff');
  else if (cff === false) cliArgs.push('--no-cff');
  if (envFork === true) cliArgs.push('--env-fork');
  else if (envFork === false) cliArgs.push('--no-env-fork');
  if (hardcodeGlobals === true) cliArgs.push('--hardcode-globals');
  else if (hardcodeGlobals === false) cliArgs.push('--no-hardcode-globals');
  if (genesis === true) cliArgs.push('--genesis');
  else if (genesis === false) cliArgs.push('--no-genesis');
  if (vmAntianalysis === true) cliArgs.push('--vm-antianalysis');
  else if (vmAntianalysis === false) cliArgs.push('--no-vm-antianalysis');
  const res = await exec(process.env.LUA_BIN || 'lua', cliArgs, {
    cwd: st.dir,
    timeoutMs: limit + 20000,
  });
  let wrote = false;
  try { wrote = isFile(outputPath) && fs.statSync(outputPath).size > 0; } catch { wrote = false; }
  const wroteLine = (res.stdout.match(/^wrote .*$/m) || [])[0] || null;
  return {
    ok: wrote,
    wrote,
    outputPath,
    level: lvl,
    seed: seed ?? null,
    wroteLine: wroteLine ? wroteLine.trim() : null,
    usingParanoid: lvl === 'paranoid',
    log: res.log,
    timedOut: res.timedOut,
    exitCode: res.code,
    artifacts: newArtifacts(path.dirname(outputPath), before),
    error: wrote ? null : (res.timedOut
      ? 'timed out — raise TOOL_TIMEOUT_LUAMULLVAD_MS for large scripts'
      : (res.log.slice(-1400) || 'no output written')),
  };
}

module.exports = {
  TOOLS_DIR,
  DIRS,
  PYTHON,
  TIMEOUTS,
  WORKSPACE,
  luauBin,
  status,
  allStatus,
  exec,
  withToolLock,
  listArtifacts,
  luast,
  luraph,
  luraphV14,
  ironbrew1,
  luamullvad,
  luarmorProbe,
  fetchInit,
  luarmorFetch,
  flowauth,
};