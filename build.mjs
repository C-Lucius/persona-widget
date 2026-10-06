#!/usr/bin/env node
// Encrypts a plaintext page into a password-gated index.html for GitHub Pages.
//
//   node build.mjs [--in src/index.html] [--out index.html]
//
// The password comes from PERSONA_PASSWORD or a hidden prompt; it is never
// written anywhere. Only ciphertext is published: AES-256-GCM with a key
// derived by PBKDF2-SHA256 (600k iterations) from the password and a fresh
// random salt. The plaintext source (src/) is gitignored — never commit it.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { createInterface } from 'node:readline';

const ITERATIONS = 600000;
const args = process.argv.slice(2);
const arg = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const inPath = arg('--in', 'src/index.html');
const outPath = arg('--out', 'index.html');

// Reads a line from the terminal without echoing it (raw mode, so readline
// can't redraw the prompt on each keystroke). Falls back to a plain line read
// when stdin isn't a TTY (e.g. piped input).
let pipedLines; // one shared reader for piped stdin, so no buffered lines are lost
function nextPipedLine() {
  if (!pipedLines) {
    const queue = [], waiting = [];
    createInterface({ input: process.stdin }).on('line', (l) => { waiting.length ? waiting.shift()(l) : queue.push(l); });
    pipedLines = () => new Promise((resolve) => { queue.length ? resolve(queue.shift()) : waiting.push(resolve); });
  }
  return pipedLines();
}

function promptHidden(question) {
  process.stdout.write(question);
  if (!process.stdin.isTTY) {
    return nextPipedLine().then((line) => { process.stdout.write('\n'); return line; });
  }
  return new Promise((resolve) => {
    let value = '';
    const onData = (chunk) => {
      // Strip terminal escape sequences — notably the bracketed-paste markers
      // (ESC[200~ … ESC[201~) many terminals wrap pasted text in. Left in, they
      // make a pasted password differ from a typed one.
      const text = chunk.toString('utf8').replace(/\x1b\[[0-9;]*[~A-Za-z]/g, '');
      for (const ch of text) {
        if (ch === '\r' || ch === '\n') {
          process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off('data', onData);
          process.stdout.write('\n'); resolve(value); return;
        }
        if (ch === '\u0003') { process.stdin.setRawMode(false); process.stdout.write('\n'); process.exit(130); } // Ctrl-C
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1); // Backspace
        else if (ch >= ' ') value += ch;
      }
    };
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.on('data', onData);
  });
}

async function getPassword() {
  if (process.env.PERSONA_PASSWORD) return process.env.PERSONA_PASSWORD;
  const a = await promptHidden('Password: ');
  const b = await promptHidden('Confirm password: ');
  if (a !== b) throw new Error('Passwords do not match.');
  return a;
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

const plaintext = readFileSync(inPath, 'utf8');
// Input problems are expected (typos, short passwords): say so in one line
// and leave index.html untouched, rather than dumping a stack trace.
function fail(msg) { console.error(`${msg} Nothing was written — run it again.`); process.exit(1); }
const password = await getPassword().catch((e) => fail(e.message));
if (password.length < 12) fail('Use at least 12 characters — the page is public, so the password is the only protection.');

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
  baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));

const payload = JSON.stringify({ v: 1, it: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
writeFileSync(outPath, gatePage(payload));
console.log(`Encrypted ${inPath} → ${outPath} (${Math.round(ct.byteLength / 1024)} KB)`);

// The gate decrypts in the browser with WebCrypto, then replaces itself with
// the page. "Remember me" stores the derived key (not the password) for this
// salt only, so rebuilding with a new password invalidates every saved key.
function gatePage(payload) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Product Personas</title>
<link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root { --accent: #096179; --ink: #172B4D; --ink-soft: #5E6C84; --line: #E4E7EC; --bg: #FFFFFF; }
  * { box-sizing: border-box; }
  html, body { margin: 0; min-height: 100%; background: var(--bg); color: var(--ink); font-family: "Figtree", system-ui, sans-serif; }
  /* Same one-border frame as the unlocked page, so the embed keeps its edge on a white page. */
  html, body { height: 100%; }
  .gate { height: 100%; display: flex; align-items: center; justify-content: center; padding: 24px 16px; border: 1px solid #DCE2E9; border-radius: 16px; background: #F6F8FA; overflow: auto; }
  form { width: 100%; max-width: 380px; background: #fff; border-radius: 16px; padding: 28px 26px; box-shadow: 0 1px 3px rgba(9,30,66,.08), 0 12px 28px rgba(9,30,66,.08); }
  .eyebrow { font-family: "Figtree", sans-serif; font-weight: 700; font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--accent); margin: 0 0 6px; }
  h1 { font-family: "Figtree", sans-serif; font-size: 22px; margin: 0 0 6px; }
  p.sub { font-size: 13.5px; color: var(--ink-soft); margin: 0 0 18px; line-height: 1.45; }
  label.f { display: block; font-size: 12px; font-weight: 700; color: var(--ink-soft); margin-bottom: 6px; }
  input[type=password] { width: 100%; height: 42px; border: 1px solid #C9D1DB; border-radius: 9px; padding: 0 12px; font: inherit; font-size: 15px; }
  input[type=password]:focus { outline: 2px solid var(--accent); outline-offset: 1px; border-color: var(--accent); }
  .row { display: flex; align-items: center; gap: 8px; margin: 12px 0 18px; font-size: 13px; color: var(--ink-soft); }
  button { width: 100%; height: 42px; border: 0; border-radius: 9px; background: var(--accent); color: #fff; font: inherit; font-weight: 700; font-size: 14px; cursor: pointer; }
  button[disabled] { opacity: .6; cursor: progress; }
  .err { color: #B3261E; font-size: 13px; min-height: 18px; margin: 10px 0 0; }
  .contact { font-size: 12.5px; color: var(--ink-soft); margin: 6px 0 0; padding-top: 14px; border-top: 1px solid var(--line); line-height: 1.45; }
  .contact b { color: var(--accent); }
</style>
</head><body>
<div class="gate">
  <form id="f" autocomplete="off">
    <p class="eyebrow">AbsenceSoft · Internal</p>
    <h1>Product Personas</h1>
    <p class="sub">This page is for AbsenceSoft team members. Enter the team password to continue.</p>
    <label class="f" for="pw">Password</label>
    <input type="password" id="pw" required autofocus>
    <label class="row"><input type="checkbox" id="rm" checked> Remember me on this browser</label>
    <button type="submit" id="go">Unlock</button>
    <p class="err" id="err" role="alert"></p>
    <p class="contact">Need access or the password? Contact Corey &mdash; <b>clucius@</b></p>
  </form>
</div>
<script>
(function () {
  var P = ${payload};
  var STORE = 'personaKey:' + P.salt;
  function bytes(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
  // document.open() only replaces the page once the gate has finished
  // loading; called earlier (the remembered-key path can be that fast) it
  // appends the decrypted page to the gate instead.
  function show(html) {
    function swap() { document.open(); document.write(html); document.close(); }
    if (document.readyState === 'complete') swap(); else window.addEventListener('load', swap);
  }
  function decrypt(key) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(P.iv) }, key, bytes(P.ct))
      .then(function (buf) { return new TextDecoder().decode(buf); });
  }
  function keyFromPassword(pw) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: bytes(P.salt), iterations: P.it },
          base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
      });
  }
  function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function save(k, v) {
    try {
      // Drop keys saved for earlier builds (old salts) — they can't decrypt anything now.
      Object.keys(localStorage).forEach(function (o) { if (o.indexOf('personaKey:') === 0 && o !== k) localStorage.removeItem(o); });
      localStorage.setItem(k, v);
    } catch (e) {}
  }
  function drop(k) { try { localStorage.removeItem(k); } catch (e) {} }

  var saved = load(STORE);
  if (saved) {
    crypto.subtle.importKey('jwk', JSON.parse(saved), { name: 'AES-GCM' }, true, ['decrypt'])
      .then(decrypt).then(show).catch(function () { drop(STORE); });
  }

  document.getElementById('f').addEventListener('submit', function (e) {
    e.preventDefault();
    var go = document.getElementById('go'), err = document.getElementById('err');
    go.disabled = true; go.textContent = 'Unlocking…'; err.textContent = '';
    var key;
    keyFromPassword(document.getElementById('pw').value)
      .then(function (k) { key = k; return decrypt(k); })
      .then(function (html) {
        if (!document.getElementById('rm').checked) return show(html);
        return crypto.subtle.exportKey('jwk', key).then(function (jwk) { save(STORE, JSON.stringify(jwk)); show(html); });
      })
      .catch(function () {
        go.disabled = false; go.textContent = 'Unlock';
        err.textContent = 'That password didn’t work. Try again.';
      });
  });
})();
</script>
</body></html>
`;
}
