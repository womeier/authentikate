# authentikate

An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq.

## Building

Prebuilt artifacts are available via womeier's cachix.
```
cachix use womeier  # optional
nix build
```

## CertiRocq

A custom [version](https://github.com/womeier/certirocq/tree/imports) of CertiRocq is used.
It has experimental support for forein function calls resolved via Wasm module imports.
