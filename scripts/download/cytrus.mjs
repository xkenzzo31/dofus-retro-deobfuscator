/**
 * cytrus.mjs — Cytrus v6 API client
 *
 * Fetches game metadata and assets from Ankama's Cytrus CDN.
 *
 * Author: Luska
 */
import https from 'node:https';

const CYTRUS_BASE = 'https://cytrus.cdn.ankama.com';

/**
 * HTTP GET returning a Buffer. Follows redirects.
 */
function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Zaap 3.14.2' } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetch(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        res.resume();
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function fetchJSON(url) {
  return fetch(url).then((buf) => JSON.parse(buf.toString()));
}

/**
 * Fetch game info from the Cytrus index.
 *
 * @param {string} game - Game identifier (e.g. 'retro')
 * @param {string} release - Release channel (e.g. 'main')
 * @returns {{ name, gameId, release, platforms, metaHash }}
 */
export async function getGameInfo(game = 'retro', release = 'main') {
  const cytrus = await fetchJSON(`${CYTRUS_BASE}/cytrus.json`);
  const entry = cytrus.games?.[game];
  if (!entry) {
    throw new Error(`Game "${game}" not found. Available: ${Object.keys(cytrus.games).join(', ')}`);
  }

  const platforms = {};
  for (const [platform, releases] of Object.entries(entry.platforms || {})) {
    if (releases[release]) {
      platforms[platform] = releases[release];
    }
  }

  return {
    name: entry.name,
    gameId: entry.gameId,
    release,
    platforms,
    metaHash: entry.assets?.meta?.[release],
  };
}

/**
 * Download the FlatBuffers manifest for a game/platform/version.
 */
export async function downloadManifest(game, release, platform, version) {
  const url = `${CYTRUS_BASE}/${game}/releases/${release}/${platform}/${version}.manifest`;
  console.log(`[cytrus] Manifest: ${url}`);
  return fetch(url);
}

/**
 * Download a full bundle by its hash.
 */
export async function downloadBundle(game, hash) {
  const prefix = hash.slice(0, 2);
  return fetch(`${CYTRUS_BASE}/${game}/bundles/${prefix}/${hash}`);
}

/**
 * Download a byte range from a bundle (HTTP Range header).
 */
export function downloadBundleRange(game, hash, offset, size) {
  const prefix = hash.slice(0, 2);
  const url = `${CYTRUS_BASE}/${game}/bundles/${prefix}/${hash}`;
  return new Promise((resolve, reject) => {
    https.get(url, {
      headers: {
        'User-Agent': 'Zaap 3.14.2',
        'Range': `bytes=${offset}-${offset + size - 1}`,
      },
    }, (res) => {
      if (res.statusCode !== 206 && res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for range request`));
        res.resume();
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

export { fetch, fetchJSON, CYTRUS_BASE };
