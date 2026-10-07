// Zero-dependency ZIP packager for the browser extension (Chrome Web Store / Edge Add-ons
// both just want a .zip of the unpacked extension folder). Implemented by hand instead of
// pulling in a zip library, since this only needs the STORE/DEFLATE subset of the format.
import { readFile, writeFile, mkdir, readdir, stat } from "node:fs/promises";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const __dirname = dirname(fileURLToPath(import.meta.url));
const extRoot = join(__dirname, "..");
const outFile = join(extRoot, "dist-zip", "secure-checker-extension.zip");

const INCLUDE = ["manifest.json", "popup.html", "icons", "dist"];

async function collectFiles(root, relBase = "") {
  const entries = [];
  const items = await readdir(join(root, relBase), { withFileTypes: true });
  for (const item of items) {
    const rel = relBase ? `${relBase}/${item.name}` : item.name;
    if (item.isDirectory()) {
      entries.push(...(await collectFiles(root, rel)));
    } else if (item.isFile()) {
      // Skip source maps and the zip script's own output in packaged builds.
      if (rel.endsWith(".map")) continue;
      entries.push(rel);
    }
  }
  return entries;
}

function crc32(buf) {
  let crc = 0xffffffff;
  const table = crc32.table ?? (crc32.table = buildCrcTable());
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildCrcTable() {
  const table = new Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
}

function makeZip(entries) {
  const localChunks = [];
  const centralChunks = [];
  let offset = 0;

  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name.replace(/\\/g, "/"), "utf8");
    const compressed = zlib.deflateRawSync(data);
    const crc = crc32(data);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(8, 8); // DEFLATE
    localHeader.writeUInt16LE(0, 10); // dos time
    localHeader.writeUInt16LE(0b0000000000100001, 12); // dos date: 1980-01-01
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localChunks.push(localHeader, nameBuf, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0b0000000000100001, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralChunks.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }

  const centralStart = offset;
  const centralSize = centralChunks.reduce((sum, b) => sum + b.length, 0);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralStart, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localChunks, ...centralChunks, eocd]);
}

async function main() {
  const relFiles = [];
  for (const item of INCLUDE) {
    const full = join(extRoot, item);
    const s = await stat(full).catch(() => null);
    if (!s) {
      console.warn(`skipping missing path: ${item} (did you run "npm run build" first?)`);
      continue;
    }
    if (s.isDirectory()) {
      const files = await collectFiles(extRoot, item);
      relFiles.push(...files);
    } else {
      relFiles.push(item);
    }
  }

  const entries = [];
  for (const rel of relFiles) {
    const data = await readFile(join(extRoot, rel));
    entries.push({ name: rel, data });
  }

  const zipBuffer = makeZip(entries);
  await mkdir(dirname(outFile), { recursive: true });
  await writeFile(outFile, zipBuffer);
  console.log(`Packaged ${entries.length} file(s) -> ${relative(extRoot, outFile)} (${(zipBuffer.length / 1024).toFixed(1)} KB)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
