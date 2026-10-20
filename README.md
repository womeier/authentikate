# authentikate

An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq.

## Building

Prebuilt artifacts are available via womeier's cachix.
```
cachix use womeier  # optional
nix build
```

The flake includes [rocq-base64](https://github.com/womeier/rocq-base64), built
with the same Rocq and MetaRocq toolchain as CertiRocq. The service uses its
MetaRocq bytestring instance with strict, unpadded base64url encoding.
`nix develop --command make` checks the proofs and byte/encoding regression tests.

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for forein function calls resolved via Wasm module imports.
