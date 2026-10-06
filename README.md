# persona-widget

Standalone AbsenceSoft persona widget (single HTML file, illustrations inlined).
Served via GitHub Pages for embedding in a Confluence iframe.

## Password-protected build

The published `index.html` can be an encrypted, password-gated page. Only
ciphertext is committed; the readable page lives in `src/index.html`, which is
gitignored and must never be committed.

    node build.mjs            # encrypts src/index.html -> index.html, prompts for the password

- AES-256-GCM, key from PBKDF2-SHA256 (600k iterations) + random salt; no dependencies.
- "Remember me" stores the derived key (not the password) in the browser. Every
  rebuild uses a new salt, so rebuilding with a new password signs everyone out.
- It's a shared password: anyone who has it can read the page, and there's no
  per-person revocation or audit. Rotate it by rebuilding with a new one.
