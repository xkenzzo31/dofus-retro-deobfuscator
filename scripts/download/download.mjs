/**
 * download.mjs — Reconstruct files from Cytrus v6 bundles
 *
 * Downloads game assets by fetching the manifest, locating target files,
 * and reassembling them from CDN bundles.
 *
 * Author: Luska
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getGameInfo, downloadManifest, downloadBundle, downloadBundleRange } from './cytrus.mjs';
import { parseManifest, findFile, buildDownloadPlan } from './manifest.mjs';

function detectPlatform() {
  switch (process.platform) {
    case 'darwin':  return 'darwin';
    case 'win32':   return 'windows';
    default:        return 'linux';
  }
}

/**
 * Download a specific file from a Cytrus game release.
 *
 * @param {object} opts
 * @param {string} opts.game       - Game name (default: 'retro')
 * @param {string} opts.release    - Release channel (default: 'main')
 * @param {string} opts.platform   - Platform (default: auto-detect)
 * @param {string} opts.fileName   - File to extract (default: 'main.jsc')
 * @param {string} opts.outputDir  - Output directory
 * @returns {Promise<string>} Path to the downloaded file
 */
export async function downloadFile(opts = {}) {
  const {
    game = 'retro',
    release = 'main',
    platform = detectPlatform(),
    fileName = 'main.jsc',
    outputDir = './output',
  } = opts;

  // 1. Fetch game info
  console.log(`[download] Fetching ${game}/${release}...`);
  const info = await getGameInfo(game, release);
  const version = info.platforms[platform];
  if (!version) {
    throw new Error(`No version for "${platform}". Available: ${Object.keys(info.platforms).join(', ')}`);
  }
  console.log(`[download] ${info.name} ${release} ${platform}: ${version}`);

  // 2. Download and parse manifest
  const manifestBuf = await downloadManifest(game, release, platform, version);
  const manifest = parseManifest(manifestBuf);
  const totalFiles = manifest.fragments.reduce((s, f) => s + f.files.length, 0);
  console.log(`[download] ${manifest.fragments.length} fragments, ${totalFiles} files`);

  // 3. Find target file
  const result = findFile(manifest, fileName);
  if (!result) {
    const matches = [];
    for (const frag of manifest.fragments) {
      for (const file of frag.files) {
        if (file.name.toLowerCase().includes(fileName.toLowerCase())) {
          matches.push(`  ${frag.name}/${file.name} (${file.size} bytes)`);
        }
      }
    }
    if (matches.length > 0) {
      console.log(`[download] Similar files:\n${matches.join('\n')}`);
    }
    throw new Error(`File "${fileName}" not found in manifest`);
  }

  const { fragment, file } = result;
  console.log(`[download] Found: ${file.name} in "${fragment}" (${file.size} bytes, ${file.chunks.length} chunks)`);

  // 4. Download and reassemble
  const { plan, byBundle } = buildDownloadPlan(manifest, file);
  const outputBuffer = Buffer.alloc(file.size);
  let done = 0;

  for (const [bundleHash, chunks] of byBundle) {
    console.log(`[download] Bundle ${bundleHash.slice(0, 12)}...`);
    const bundleData = await downloadBundle(game, bundleHash);

    for (const chunk of chunks) {
      process.stdout.write(`\r[download] Chunk ${++done}/${plan.length}`);
      bundleData.subarray(chunk.bundleOffset, chunk.bundleOffset + chunk.size)
        .copy(outputBuffer, chunk.fileOffset);
    }
  }
  console.log('');

  // 5. Verify SHA-1
  const computed = crypto.createHash('sha1').update(outputBuffer).digest('hex');
  if (computed !== file.hash) {
    console.warn(`[download] Hash mismatch! Expected ${file.hash}, got ${computed}`);
  } else {
    console.log(`[download] Hash OK: ${computed}`);
  }

  // 6. Write to disk
  fs.mkdirSync(outputDir, { recursive: true });
  const outputPath = path.join(outputDir, path.basename(file.name));
  fs.writeFileSync(outputPath, outputBuffer);
  console.log(`[download] Saved: ${outputPath}`);

  return outputPath;
}

/**
 * List all files in a game's manifest.
 */
export async function listFiles(opts = {}) {
  const { game = 'retro', release = 'main', platform = detectPlatform(), filter = '' } = opts;

  const info = await getGameInfo(game, release);
  const version = info.platforms[platform];
  const manifestBuf = await downloadManifest(game, release, platform, version);
  const manifest = parseManifest(manifestBuf);

  const files = [];
  for (const frag of manifest.fragments) {
    for (const file of frag.files) {
      if (!filter || file.name.toLowerCase().includes(filter.toLowerCase())) {
        files.push({ fragment: frag.name, name: file.name, size: file.size, hash: file.hash });
      }
    }
  }
  return files;
}

// --- CLI ---
if (process.argv[1]?.endsWith('download.mjs')) {
  const args = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < args.length; i += 2) {
    opts[args[i].replace(/^--/, '')] = args[i + 1];
  }

  downloadFile({
    game:     opts.game     || 'retro',
    release:  opts.release  || 'main',
    platform: opts.platform || 'linux',
    fileName: opts.file     || 'main.jsc',
    outputDir: opts.output  || './output',
  }).catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}
