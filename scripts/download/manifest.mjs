/**
 * manifest.mjs — Cytrus v6 FlatBuffers manifest parser
 *
 * Parses the binary FlatBuffers manifest that Cytrus uses to describe
 * game file layouts across bundles.
 *
 * Schema (reverse-engineered):
 *   Manifest { fragments: [Fragment] }
 *   Fragment { name, files: [File], bundles: [Bundle] }
 *   File     { name, size, hash, chunks: [Chunk], executable, symlink }
 *   Bundle   { hash, chunks: [Chunk] }
 *   Chunk    { hash, size, offset }
 *
 * Author: Luska
 */

/**
 * Minimal FlatBuffers reader — no codegen required.
 */
class FBReader {
  constructor(buf) {
    this.buf = buf;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  uint8(off)  { return this.view.getUint8(off); }
  uint16(off) { return this.view.getUint16(off, true); }
  uint32(off) { return this.view.getUint32(off, true); }
  int32(off)  { return this.view.getInt32(off, true); }
  uint64(off) {
    const lo = this.view.getUint32(off, true);
    const hi = this.view.getUint32(off + 4, true);
    return lo + hi * 0x100000000;
  }

  rootTable() {
    return this.uint32(0);
  }

  vtable(tableOff) {
    return tableOff - this.int32(tableOff);
  }

  fieldOffset(tableOff, fieldIdx) {
    const vt = this.vtable(tableOff);
    const vtSize = this.uint16(vt);
    const byteOff = 4 + fieldIdx * 2;
    if (byteOff >= vtSize) return 0;
    return this.uint16(vt + byteOff);
  }

  readString(tableOff, fieldIdx) {
    const off = this.fieldOffset(tableOff, fieldIdx);
    if (off === 0) return null;
    const strOff = tableOff + off + this.uint32(tableOff + off);
    const len = this.uint32(strOff);
    return this.buf.subarray(strOff + 4, strOff + 4 + len).toString('utf8');
  }

  readHex(tableOff, fieldIdx) {
    const off = this.fieldOffset(tableOff, fieldIdx);
    if (off === 0) return null;
    const strOff = tableOff + off + this.uint32(tableOff + off);
    const len = this.uint32(strOff);
    return Buffer.from(this.buf.subarray(strOff + 4, strOff + 4 + len)).toString('hex');
  }

  readScalar(tableOff, fieldIdx, size = 4) {
    const off = this.fieldOffset(tableOff, fieldIdx);
    if (off === 0) return 0;
    if (size === 1) return this.uint8(tableOff + off);
    if (size === 2) return this.uint16(tableOff + off);
    return this.uint32(tableOff + off);
  }

  readUint64(tableOff, fieldIdx) {
    const off = this.fieldOffset(tableOff, fieldIdx);
    if (off === 0) return 0;
    return this.uint64(tableOff + off);
  }

  readBool(tableOff, fieldIdx) {
    const off = this.fieldOffset(tableOff, fieldIdx);
    if (off === 0) return false;
    return this.uint8(tableOff + off) !== 0;
  }

  readVector(tableOff, fieldIdx) {
    const off = this.fieldOffset(tableOff, fieldIdx);
    if (off === 0) return [];
    const vecOff = tableOff + off + this.uint32(tableOff + off);
    const len = this.uint32(vecOff);
    const results = [];
    for (let i = 0; i < len; i++) {
      const elemOff = vecOff + 4 + i * 4;
      results.push(elemOff + this.uint32(elemOff));
    }
    return results;
  }
}

/**
 * Parse a Cytrus v6 manifest buffer.
 */
export function parseManifest(buf) {
  const fb = new FBReader(buf);
  const root = fb.rootTable();

  const fragments = fb.readVector(root, 0).map((fragOff) => {
    const name = fb.readString(fragOff, 0);

    const files = fb.readVector(fragOff, 1).map((fileOff) => ({
      name: fb.readString(fileOff, 0),
      size: fb.readUint64(fileOff, 1),
      hash: fb.readHex(fileOff, 2),
      chunks: fb.readVector(fileOff, 3).map((chunkOff) => ({
        hash: fb.readHex(chunkOff, 0),
        size: fb.readUint64(chunkOff, 1),
        offset: fb.readUint64(chunkOff, 2),
      })),
      executable: fb.readBool(fileOff, 4),
      symlink: fb.readString(fileOff, 5),
    }));

    const bundles = fb.readVector(fragOff, 2).map((bundleOff) => ({
      hash: fb.readHex(bundleOff, 0),
      chunks: fb.readVector(bundleOff, 1).map((chunkOff) => ({
        hash: fb.readHex(chunkOff, 0),
        size: fb.readUint64(chunkOff, 1),
        offset: fb.readUint64(chunkOff, 2),
      })),
    }));

    return { name, files, bundles };
  });

  return { fragments };
}

/**
 * Find a file by name in the parsed manifest.
 */
export function findFile(manifest, fileName) {
  for (const fragment of manifest.fragments) {
    for (const file of fragment.files) {
      if (file.name === fileName || file.name.endsWith('/' + fileName)) {
        return { fragment: fragment.name, file };
      }
    }
  }
  return null;
}

/**
 * Build a download plan mapping file chunks to their source bundles.
 */
export function buildDownloadPlan(manifest, file) {
  const chunkMap = new Map();
  for (const fragment of manifest.fragments) {
    for (const bundle of fragment.bundles) {
      for (const chunk of bundle.chunks) {
        chunkMap.set(chunk.hash, {
          bundleHash: bundle.hash,
          offsetInBundle: chunk.offset,
          size: chunk.size,
        });
      }
    }
  }

  const plan = file.chunks.map((fc) => {
    const info = chunkMap.get(fc.hash);
    if (!info) throw new Error(`Chunk ${fc.hash} not found in any bundle`);
    return {
      chunkHash: fc.hash,
      fileOffset: fc.offset,
      size: fc.size,
      bundleHash: info.bundleHash,
      bundleOffset: info.offsetInBundle,
    };
  });

  const byBundle = new Map();
  for (const entry of plan) {
    if (!byBundle.has(entry.bundleHash)) byBundle.set(entry.bundleHash, []);
    byBundle.get(entry.bundleHash).push(entry);
  }

  return { plan, byBundle };
}

export { FBReader };
