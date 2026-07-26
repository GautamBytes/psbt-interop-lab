# HWI Simulator Adapter

This adapter exercises an HWI-compatible process boundary without requiring a physical device. The
lab process enumerates a separate JSON-speaking simulator, invokes its `signtx` command, and checks
that the returned PSBT changed only by the expected P2WPKH signature.

The simulated device owns deterministic regtest scalar one, accepts only fingerprint `73c5da0a`
at `m/84'/1'/0'/0/0`, and exposes explicit approve/refuse behavior. It does not test the Bitcoin
Core HWI Python package, USB transport, secure elements, vendor firmware, PINs, or passphrases.

```bash
npm ci --ignore-scripts
npm test
npm run typecheck
```
