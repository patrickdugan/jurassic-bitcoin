import { copyFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const repo = resolve(root, '..', '..');
const outDir = resolve(root, 'public');

await mkdir(outDir, { recursive: true });

await copyOptional(
  resolve(repo, 'artifacts', 'museum', 'data.json'),
  resolve(outDir, 'data.json'),
  'museum data'
);
await copyOptional(
  resolve(repo, 'artifacts', 'grants', 'bitcoin_defi_graft_map.json'),
  resolve(outDir, 'bitcoin-defi-graft-map.json'),
  'Bitcoin DeFi graft map'
);

async function copyOptional(src, dest, label) {
  try {
    await copyFile(src, dest);
    console.log(`synced ${label}: ${src} -> ${dest}`);
  } catch (err) {
    if (err?.code === 'ENOENT') {
      console.warn(`skipped ${label}; missing ${src}`);
      return;
    }
    throw err;
  }
}
