// Reads patoshi_pubkeys_COMPLETE.csv and outputs satoshi_data.js
// Each row has an uncompressed secp256k1 pubkey (04...).
// We store hash160 = RIPEMD160(SHA256(pubkey)) for each one.
// The browser checks the same hash160 of the generated key against this Set.

import { createReadStream } from 'fs';
import { writeFile } from 'fs/promises';
import { createInterface } from 'readline';
import { createHash } from 'crypto';

// Pure-JS RIPEMD-160 (no native dependency needed)
// Ported from the reference implementation.
function ripemd160(data) {
  const ML = [
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
  ];
  const MR = [
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
  ];
  const XL = [
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
  ];
  const XR = [
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
  ];

  function f(j, x, y, z) {
    if (j <  16) return (x ^ y ^ z) >>> 0;
    if (j <  32) return ((x & y) | (~x & z)) >>> 0;
    if (j <  48) return ((x | ~y) ^ z) >>> 0;
    if (j <  64) return ((x & z) | (y & ~z)) >>> 0;
    return (x ^ (y | ~z)) >>> 0;
  }
  function rol(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const msgLen = buf.length;
  const bitLen = BigInt(msgLen) * 8n;

  // Pad
  const padLen = ((msgLen + 8) % 64 <= 55) ? 55 - ((msgLen + 8) % 64) + 8 : 119 - ((msgLen + 8) % 64) + 8;
  const padded = Buffer.alloc(msgLen + 1 + padLen + 8);
  buf.copy(padded);
  padded[msgLen] = 0x80;
  padded.writeBigUInt64LE(bitLen, padded.length - 8);

  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

  for (let i = 0; i < padded.length; i += 64) {
    const X = Array.from({length: 16}, (_, k) => padded.readUInt32LE(i + k * 4));
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    let ar = h0, br = h1, cr = h2, dr = h3, er = h4;

    for (let j = 0; j < 80; j++) {
      const kl = j < 16 ? 0x00000000 : j < 32 ? 0x5A827999 : j < 48 ? 0x6ED9EBA1 : j < 64 ? 0x8F1BBCDC : 0xA953FD4E;
      const kr = j < 16 ? 0x50A28BE6 : j < 32 ? 0x5C4DD124 : j < 48 ? 0x6D703EF3 : j < 64 ? 0x7A6D76E9 : 0x00000000;
      let tl = (rol((al + f(j, bl, cl, dl) + X[XL[j]] + kl) >>> 0, ML[j]) + el) >>> 0;
      al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = tl;
      let tr = (rol((ar + f(79 - j, br, cr, dr) + X[XR[j]] + kr) >>> 0, MR[j]) + er) >>> 0;
      ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
    }
    const t = (h1 + cl + dr) >>> 0;
    h1 = (h2 + dl + er) >>> 0; h2 = (h3 + el + ar) >>> 0;
    h3 = (h4 + al + br) >>> 0; h4 = (h0 + bl + cr) >>> 0; h0 = t;
  }

  const out = Buffer.alloc(20);
  out.writeUInt32LE(h0, 0); out.writeUInt32LE(h1, 4);
  out.writeUInt32LE(h2, 8); out.writeUInt32LE(h3, 12);
  out.writeUInt32LE(h4, 16);
  return out;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  let leading = 0;
  for (const b of buf) { if (b !== 0) break; leading++; }
  let n = BigInt('0x' + buf.toString('hex'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  return '1'.repeat(leading) + out;
}

function pubkeyToP2PKH(pubkeyHex) {
  const pub     = Buffer.from(pubkeyHex, 'hex');
  const sha1    = createHash('sha256').update(pub).digest();
  const h160    = ripemd160(sha1);
  const versioned = Buffer.alloc(21);
  versioned[0] = 0x00;
  h160.copy(versioned, 1);
  const sha2    = createHash('sha256').update(versioned).digest();
  const checksum = createHash('sha256').update(sha2).digest().subarray(0, 4);
  const full    = Buffer.concat([versioned, checksum]);
  const h160hex = h160.toString('hex');
  return { h160hex, address: base58Encode(full) };
}

const rl = createInterface({ input: createReadStream('./patoshi_pubkeys_COMPLETE.csv') });
// Map: hash160 → [address, btc]
const wallets = new Map();
let lineNo = 0;

for await (const line of rl) {
  lineNo++;
  if (lineNo === 1) continue; // header
  const cols = line.split(',');
  if (cols.length < 5) continue;
  const pubkey = cols[2].trim();
  if (pubkey.length < 130) continue; // must be full uncompressed pubkey (130 hex chars)
  const btc = parseFloat(cols[3]);
  const { h160hex, address } = pubkeyToP2PKH(pubkey);
  if (!wallets.has(h160hex)) wallets.set(h160hex, [address, btc]);
}

// Serialise as array of [hash160, address, btc] triples for compact JSON
const entries = [...wallets.entries()].map(([h, [a, b]]) => [h, a, b]);
const totalBtc = entries.reduce((s, e) => s + e[2], 0);

const js = `// Auto-generated by build_data.mjs — DO NOT EDIT
// ${wallets.size} unique Patoshi wallets · total ~${Math.round(totalBtc).toLocaleString()} BTC
// Format: Map<hash160, [p2pkh_address, btc_amount]>
const _SD = ${JSON.stringify(entries)};
const SATOSHI_HASH160 = new Map(_SD.map(([h,a,b]) => [h, [a, b]]));
const SATOSHI_WALLET_COUNT = ${wallets.size};
const SATOSHI_TOTAL_BTC = ${Math.round(totalBtc)};
`;

await writeFile('./satoshi_data.js', js, 'utf8');
console.log(`Done. ${wallets.size} wallets → satoshi_data.js  (total ${Math.round(totalBtc).toLocaleString()} BTC)`);
