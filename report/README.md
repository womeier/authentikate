Written by LLMs. TODO: check.

# Building the report

Run the watcher from the repository root:

```sh
nix run .#report-watch
```

The command builds once, then Watchman rebuilds whenever a TeX or BibTeX file under
`report/` changes. The PDF is written to `build/report/main.pdf`.
Build errors do not stop the watcher. Press Ctrl+C to stop watching.

## References

Bibliography entries live in `refs.bib`. Cite them with `\cite{key}` or
`\textcite{key}`. Cited entries appear in the bibliography at the end of the
report. Tectonic runs the BibTeX backend automatically; Biber is not required.

Restart an already running watcher to enable rebuilds on `.bib` changes.

## Architecture Figure

Whenever a WIT interface changes, update `architecture.tex` in the same change
so the component diagram stays consistent with the implementation. Simplified
signatures may omit details, but must preserve argument and result semantics.

The overview in `composed-component.tex` shows the final component. Its listing
in `composed-interface.tex` contains the root-world output of
`wasm-tools component wit build/host.component.wasm`, with imports grouped and
dependency definitions omitted. When composition changes, rebuild with
`make compose-host` and refresh that listing and the overview as needed.
