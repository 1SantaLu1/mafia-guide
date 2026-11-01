// Recomputes the SHA-256 hashes of the page's single inline <script> and single
// inline <style> and writes them into the Content-Security-Policy meta tag of
// index.html (script-src and style-src).
//
// Run after ANY edit of the inline script or style:   node tools/update-csp.mjs
// With --check it only verifies (exit code 1 when a hash is stale).
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const file = fileURLToPath(new URL('../index.html', import.meta.url));
const html = readFileSync(file, 'utf8');
const hashOf = text => 'sha256-' + createHash('sha256').update(text, 'utf8').digest('base64');

let next = html;
for (const [tag, directive] of [['script', 'script-src'], ['style', 'style-src']]) {
  const blocks = [...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g'))];
  if (blocks.length !== 1) { console.error(`expected exactly one inline <${tag}>, found ${blocks.length}`); process.exit(2); }
  const re = new RegExp(`(${directive} )'sha256-[^']*'`);
  if (!re.test(next)) { console.error(`CSP meta tag with ${directive} not found`); process.exit(2); }
  next = next.replace(re, `$1'${hashOf(blocks[0][1])}'`);
}
if (process.argv.includes('--check')) {
  if (next !== html) { console.error('CSP hashes are stale: run `node tools/update-csp.mjs`'); process.exit(1); }
  console.log('CSP hashes are up to date'); process.exit(0);
}
if (next !== html) writeFileSync(file, next);
console.log(next !== html ? 'updated CSP hashes' : 'CSP hashes already up to date');
