// Run once with network access. The application itself never downloads from a CDN.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const clientRoot = fileURLToPath(new URL('../', import.meta.url));
const assetRoot = path.join(clientRoot, 'public', 'tesseract');
const maxBytes = 5_000_000;
const dataSource = 'https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/4.1.0';
const expectedHashes = {
  'eng.traineddata': '7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2',
  'hin.traineddata': '4c73ffc59d497c186b19d1e90f5d721d678ea6b2e277b719bee4e2af12271825',
  LICENSE: 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30',
};
const sha256 = data => createHash('sha256').update(data).digest('hex');

async function save(relativePath, data) {
  if (data.length > maxBytes) throw new Error(`${relativePath} exceeds the 5 MB asset limit.`);
  const target = path.join(assetRoot, relativePath);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, data);
  console.log(`${relativePath}: ${data.length} bytes; SHA256 ${sha256(data)}`);
}

async function copy(packageName, source, destination) {
  await save(destination, await readFile(path.join(clientRoot, 'node_modules', packageName, source)));
}

async function download(name, destination) {
  try {
    const existing = await readFile(path.join(assetRoot, destination));
    if (sha256(existing) === expectedHashes[name]) {
      console.log(`${destination}: verified existing local asset (${existing.length} bytes)`);
      return;
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const response = await fetch(`${dataSource}/${name}`, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error(`Could not download ${name}: HTTP ${response.status}`);
  if (Number(response.headers.get('content-length')) > maxBytes) throw new Error(`${name} exceeds the 5 MB asset limit.`);
  const data = Buffer.from(await response.arrayBuffer());
  if (sha256(data) !== expectedHashes[name]) throw new Error(`Checksum verification failed for ${name}.`);
  await save(destination, data);
}

for (const packageName of ['tesseract.js', 'tesseract.js-core']) {
  const metadata = JSON.parse(await readFile(path.join(clientRoot, 'node_modules', packageName, 'package.json'), 'utf8'));
  if (metadata.version !== '5.1.1') throw new Error(`Expected ${packageName} 5.1.1; review OCR compatibility before upgrading.`);
}

await copy('tesseract.js', 'dist/worker.min.js', 'worker.min.js');
await copy('tesseract.js', 'dist/worker.min.js.LICENSE.txt', 'worker.min.js.LICENSE.txt');
await copy('tesseract.js', 'LICENSE.md', 'licenses/tesseract.js.LICENSE');
await copy('tesseract.js-core', 'LICENSE', 'licenses/tesseract.js-core.LICENSE');

// These four bundles embed their WASM binaries. Keep both SIMD and non-SIMD variants.
for (const name of ['tesseract-core', 'tesseract-core-simd', 'tesseract-core-lstm', 'tesseract-core-simd-lstm']) {
  await copy('tesseract.js-core', `${name}.wasm.js`, `core/${name}.wasm.js`);
}

await download('eng.traineddata', 'lang-data/eng.traineddata');
await download('hin.traineddata', 'lang-data/hin.traineddata');
await download('LICENSE', 'licenses/tessdata_fast.LICENSE');
console.log('Local English + Hindi OCR assets are ready. Runtime requests stay on localhost.');
