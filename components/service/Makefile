.DEFAULT_GOAL := component

rocq: Makefile.rocq
	@mkdir -p ../../build
	@+$(MAKE) -f Makefile.rocq $(if $(wildcard ../../build/Authentikate.extraction.authentikate_api.wasm),,-W theories/extraction.v) all

component: rocq
	node build.mjs

test: component
	node ../../tests/ffi-adapters.mjs ../../build
	node ../../tests/component.mjs ../../build

clean: Makefile.rocq
	@+$(MAKE) -f Makefile.rocq cleanall
	@rm -f Makefile.rocq Makefile.rocq.conf ../../build/*.wasm

Makefile.rocq: _RocqProject
	$(COQBIN)rocq makefile -f _RocqProject -o Makefile.rocq

force _RocqProject Makefile: ;

%: Makefile.rocq force
	@mkdir -p ../../build
	@+$(MAKE) -f Makefile.rocq $@

.PHONY: rocq component test clean force
