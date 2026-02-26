import { copyFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const repo = resolve(root, '..', '..');
const src = resolve(repo, 'artifacts', 'museum', 'data.json');
const outDir = resolve(root, 'public');
const dest = resolve(outDir, 'data.json');

await mkdir(outDir, { recursive: true });
await copyFile(src, dest);
console.log(`synced museum data: ${src} -> ${dest}`);
