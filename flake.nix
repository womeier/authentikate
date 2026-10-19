{
  description = "An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # Linux x86_64 only, on purpose: the one platform this is developed on.
      # The Wasm the build produces is platform-independent anyway.
      system = "x86_64-linux";
      lib = nixpkgs.lib;

      pkgs = import nixpkgs {
        inherit system;
        # CertiRocq depends on CompCert (unfree) for its Clight backend.
        config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "compcert" ];
      };

      # One Rocq 9.1 toolchain.  Everything lives in rocqPackages_9_1: the
      # rocq core, the Coq-named compatibility packages (coqc, which
      # CertiRocq's plugin needs), CertiRocq itself and the stdlib.
      # WasmCert (nixpkgs' coq-wasm) is pinned to 2.2.1: nixpkgs pairs Rocq
      # 9.1 with WasmCert 2.2.0 because released CertiRocq 0.9.1+9.1 requires
      # exactly that, but the womeier fork below needs 2.2.1.  The over-scoped
      # CertiRocq takes its released version explicitly, since nixpkgs'
      # default only picks one for WasmCert 2.2.0; that key just fixes the
      # fetched tarball (discarded below) and the derivation name.
      rocqPackages = pkgs.rocqPackages_9_1.overrideScope (_self: super:
        let
          wasmcert = super.wasmcert.override { version = "2.2.1"; };
        in
        {
          inherit wasmcert;
          CertiRocq = super.CertiRocq.override {
            inherit wasmcert;
            version = "0.9.1+9.1";
          };
        });

      # CertiRocq itself: nixpkgs' Rocq 9.1 package, overwritten to build from
      # the womeier fork (github.com/womeier/CertiRocq) at one pinned commit
      # instead of a released tarball.
      CertiRocq = rocqPackages.CertiRocq.overrideAttrs (_old: {
        version = "unstable-6d34b50b";
        src = pkgs.fetchFromGitHub {
          owner = "womeier";
          repo = "CertiRocq";
          rev = "6d34b50bfea92aece62712ae120890c9fda8e514";
          hash = "sha256-7NVJcNfX/q59iDA7/Y0cb8CsgP5E1iddqW/Emk4f9mE=";
        };
      });

      # Rocq sources and the build driver.  Keeps build products and editor
      # leftovers out of the derivation.
      src = lib.cleanSourceWith {
        src = ./.;
        filter =
          path: type:
          type == "directory"
          || lib.hasSuffix ".v" path
          || lib.elem (baseNameOf path) [
            "Makefile"
            "_RocqProject"
          ];
      };

      # The service as a single Wasm module, compiled by CertiRocq from
      # theories/extraction.v.
      authentikate-wasm = pkgs.stdenv.mkDerivation {
        pname = "authentikate-wasm";
        version = "0.1.0";
        inherit src;

        nativeBuildInputs = [
          rocqPackages.coq
          CertiRocq
        ];

        COQBIN = "${rocqPackages.coq}/bin/";

        buildPhase = ''
          runHook preBuild
          ulimit -s unlimited 2>/dev/null || true
          make -j $NIX_BUILD_CORES
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out
          cp *.wasm $out/
          runHook postInstall
        '';

        meta = {
          description = "An authentication backend in Rocq, compiled to WebAssembly by CertiRocq";
          license = lib.licenses.mit;
          platforms = [ system ];
        };
      };
    in
    {
      packages.${system} = {
        default = authentikate-wasm;
        inherit authentikate-wasm;
        # The heavy prebuilt dependency, exposed so CI can fetch it
        # substitute-only before building anything:
        #   nix build --max-jobs 0 .#CertiRocq
        # (It substitutes from womeier.cachix.org when the store path
        # matches; otherwise it rebuilds from the fork.)
        inherit CertiRocq;
      };

      # The proofs are checked by building, so building is the test suite.
      checks.${system}.build = authentikate-wasm;

      devShells.${system}.default = pkgs.mkShell {
        name = "authentikate";
        packages = [
          rocqPackages.rocq-core
          rocqPackages.coq
          CertiRocq
          rocqPackages.stdlib
          rocqPackages.coq-lsp
          pkgs.gnumake

          # The host wrapper runs the module under Node.
          pkgs.nodejs

          # The crypto primitives come from a Rust library, linked in through
          # the module's imports.
          pkgs.cargo
          pkgs.rustc
          pkgs.rustfmt
          pkgs.clippy
          pkgs.rust-analyzer
          # The wasm32 target links with lld, which nixpkgs' rustc does not
          # bundle as rust-lld.
          pkgs.lld

          # To look at what came out, and to inspect the module's imports.
          pkgs.wabt # wasm2wat
          pkgs.wasm-tools
        ];

        COQBIN = "${rocqPackages.coq}/bin/";

        shellHook = ''
          echo "authentikate development environment"
          echo "  rocq:  $(rocq --version | head -1)"
          echo "  node:  $(node --version)"
          echo "  rustc: $(rustc --version)"
          echo ""
          echo "Build the Wasm module:  make        (or: nix build)"
        '';
      };
    };
}
