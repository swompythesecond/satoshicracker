# Satoshi Cracker

**Live at [satoshicracker.com](https://satoshicracker.com)**

A browser-based tool that generates real Bitcoin private keys using actual secp256k1 elliptic curve cryptography and checks each one against Satoshi Nakamoto's Genesis Block wallet (`1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`).

No simulation — real cryptography, running client-side in your browser.

## How it works

1. Generates a cryptographically random 256-bit private key
2. Derives the compressed public key via secp256k1 scalar multiplication
3. Applies SHA-256 → RIPEMD-160 → Base58Check to produce a P2PKH address
4. Compares it against Satoshi's address
5. Repeats as fast as your CPU allows

## Odds

The Bitcoin keyspace is 2²⁵⁶ ≈ 1.16 × 10⁷⁷. The probability of any single attempt succeeding is essentially zero — but never exactly zero. Every key has an equal, nonzero chance.

## Stack

- Pure HTML/CSS/JS — no build step, no framework
- [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) for elliptic curve math
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) for SHA-256 and RIPEMD-160
- Live BTC price via Binance public API
- Live wallet balance via blockchain.info

## Running locally

```bash
git clone https://github.com/swompythesecond/satoshicracker
cd satoshicracker
# open index.html in any modern browser
# or serve it:
npx serve .
```

Requires internet access to load the crypto libraries from the esm.sh CDN and fetch live BTC data.

## License

MIT
