// Recomputes the SHA-256 of the page's inline <script> and writes it into the
// Content-Security-Policy meta tag of index.html.
//
// Run after ANY edit of the inline script:   node tools/update-csp.mjs
// With --check it only verifies (exit code 1 when the hash is stale).
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const file = fileURLToPath(new URL('../index.html', import.meta.url));
const html = readFileSync(file, 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (scripts.length !== 1) { console.error(`expected exactly one inline <script>, found ${scripts.length}`); process.exit(2); }
const hash = 'sha256-' + createHash('sha256').update(scripts[0][1], 'utf8').digest('base64');
const re = /(script-src )'sha256-[^']*'/;
if (!re.test(html)) { console.error('CSP meta tag with script-src not found'); process.exit(2); }
const next = html.replace(re, `$1'${hash}'`);
if (process.argv.includes('--check')) {
  if (next !== html) { console.error('CSP hash is stale: run `node tools/update-csp.mjs`'); process.exit(1); }
  console.log('CSP hash is up to date'); process.exit(0);
}
if (next !== html) writeFileSync(file, next);
console.log(next !== html ? `updated: ${hash}` : `already up to date: ${hash}`);
