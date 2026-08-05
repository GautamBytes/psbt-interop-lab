# Scure MuSig2 Signer Adapter

This adapter supplies participant two in the bundled BIP373 proof. It uses
`@scure/btc-signer` 2.2.0 for BIP327 MuSig2 while participant one uses the Rust `musig2` 0.4.1
crate. The lab exchanges their public nonces and partial signatures, verifies both contributions,
aggregates a BIP340 signature, and requires Bitcoin Core to accept the resulting Taproot spend.

The signer accepts only the committed public `p2tr-musig2` regtest fixture, including its separately
authorized witness value. Secret nonces are kept in bounded process memory, expire after 15 minutes,
are consumed once, and are explicitly zeroed when discarded. The fixed scalar two is public test
material with no economic value.

```bash
npm ci --ignore-scripts
npm test
npm run typecheck
```
