# Included by the root Makefile; paths are relative to the repository root.
rocq: Makefile.rocq
	@mkdir -p build
	@+$(MAKE) -f Makefile.rocq $(if $(wildcard build/Authentikate.extraction.authentikate_api.wasm),,-W components/service/theories/extraction.v) all

component: rocq
	node components/service/build.mjs

test: component
	node tests/ffi-adapters.mjs
	node tests/component.mjs

clean: Makefile.rocq
	@+$(MAKE) -f Makefile.rocq cleanall
	@rm -f Makefile.rocq Makefile.rocq.conf build/*.wasm

Makefile.rocq: _RocqProject
	$(COQBIN)rocq makefile -f _RocqProject -o Makefile.rocq

force _RocqProject Makefile components/service/Makefile: ;

%: Makefile.rocq force
	@mkdir -p build
	@+$(MAKE) -f Makefile.rocq $@

.PHONY: rocq component test clean force
