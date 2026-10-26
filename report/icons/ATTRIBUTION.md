# Diagram Logo Assets

Retrieved 2026-10-26 from the official project repositories. These are actual
project logos, not redrawn approximations. Both PDFs contain black vector paths
on a transparent background, with no embedded raster images or required fonts.
The Rocq asset is the compact icon only, not the wide wordmark.

| Ready-to-use PDF | SVG source | PDF page size (PostScript points) | SVG dimensions |
| --- | --- | --- | --- |
| `rust-logo-black.pdf` | `rust-logo-black.svg` | 78.7516 x 78.7509 | 27.781801 x 27.781572 mm |
| `rocq-icon-black.pdf` | `rocq-icon-black.svg` | 246.322 x 210.277 | viewBox 0 0 328.43 280.37 |

PDF dimensions use 72 points per inch. Scale proportionally when including these
files; neither needs shell escape or SVG conversion during the LaTeX build.

```latex
\includegraphics[height=5mm]{icons/rust-logo-black.pdf}
\includegraphics[height=5mm]{icons/rocq-icon-black.pdf}
```

## Rust

- Attribution: Rust logo, Rust project; distributed by `rust-lang/rust-artwork`.
- Official source: <https://github.com/rust-lang/rust-artwork>.
- Revision: `7b54b6689dc310db2f301d7bcda847f016bd447c`.
- Download: <https://raw.githubusercontent.com/rust-lang/rust-artwork/7b54b6689dc310db2f301d7bcda847f016bd447c/logo/rust-logo-single-path.svg>.
- License: Creative Commons Attribution 4.0 International (CC-BY-4.0), <https://creativecommons.org/licenses/by/4.0/>.
- Upstream copyright, license, and trademark notice preserved in `rust-logo-LICENSE.md`.
- Changes: SVG renamed only, with no content changes; converted to PDF. The official single-path variant avoids SVG masks and preserves vector geometry in PDF.
- Rust logos and the Rust/Cargo names are registered trademarks. Usage must not imply endorsement. See <https://rustfoundation.org/policy/rust-trademark-policy/>.

## Rocq Prover

- Attribution: Rocq Prover logo, `rocq-prover.org` project.
- Official source: <https://github.com/rocq-prover/rocq-prover.org>.
- Revision: `5e57f4646032070f124b847d50b3005a22b2cb00`.
- Download: <https://raw.githubusercontent.com/rocq-prover/rocq-prover.org/5e57f4646032070f124b847d50b3005a22b2cb00/asset/logos/icon-rocq-orange.svg>.
- License: Unlicense (public-domain dedication), <https://unlicense.org/>. The upstream `LICENSE` explicitly states: "Rocq logo is released under the UNLICENSE."
- Upstream license declaration and full Unlicense text preserved in `rocq-upstream-LICENSE.txt`. The site's general CC-BY-SA content license is not the logo license.
- Unmodified downloaded source preserved as `rocq-icon-orange.original.svg`.
- Changes in `rocq-icon-black.svg`: fill `#ff540a` replaced with `#000000`, plus a final newline. Path geometry and viewBox are unchanged. Converted to PDF.

## Reproduce PDFs

Run from `report/`. These commands use librsvg 2.62.3 from the existing project's
locked nixpkgs revision, without editing the flake or compiling the report.

```sh
nix shell github:womeier/nixpkgs/bc27a0a10b7f6da40b9c9c69cb4296521790a5a9#librsvg --command rsvg-convert --format pdf --output icons/rust-logo-black.pdf icons/rust-logo-black.svg
nix shell github:womeier/nixpkgs/bc27a0a10b7f6da40b9c9c69cb4296521790a5a9#librsvg --command rsvg-convert --format pdf --output icons/rocq-icon-black.pdf icons/rocq-icon-black.svg
```

Validation: `pdfinfo` reports one page per file and the dimensions above;
`pdfimages -list` reports no raster images for either PDF.
