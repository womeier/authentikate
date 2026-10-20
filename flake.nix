{
  description = "An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.rocq-base64 = {
    url = "github:womeier/rocq-base64";
    flake = false;
  };

  outputs =
    { self, nixpkgs, rocq-base64 }:
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

      # One Rocq 9.1 toolchain.
      # Two dependencies are different:
      #   * WasmCert (nixpkgs' coq-wasm) 2.2.1 instead of 2.2.0.
      #   * MetaRocq from its "9.1" development branch instead of the 1.5.1-9.1
      #     release.  CertiRocq has needed that branch since
      #     https://github.com/CertiRocq/certirocq/pull/158, and its own
      #     .nix/config.nix pins `metarocq.override.version = "9.1"`
      #     accordingly; the fork's config.nix says the same.
      rocqPackages = pkgs.rocqPackages_9_1.overrideScope (_self: super:
        let
          wasmcert = super.wasmcert.override { version = "2.2.1"; };
          metarocq = super.metarocq.override {
            version = {
              version = "unstable-c8cd4605";
              location = {
                rev = "c8cd46054518193103c3bb33aa6e15c7f489e72c";
                hash = "sha256-Lcr6B4gYSS57zVinn+e2tk1Kfy9XzJs+sd3CTuSTvX0=";
              };
            };
          };
        in
        {
          inherit wasmcert metarocq;
        });

      base64 =
        (rocqPackages.callPackage "${rocq-base64}/.nix/rocq-overlays/base64/default.nix" { })
        .overrideAttrs (old: {
          version = "unstable-${builtins.substring 0 8 rocq-base64.rev}";
          src = rocq-base64;
        });

      # CertiRocq's own sources at one pinned commit of the womeier fork
      # (github.com/womeier/CertiRocq), used both as the package's src and as
      # the place its Nix build recipe is pulled from below.
      certirocqSrc = pkgs.fetchFromGitHub {
        owner = "womeier";
        repo = "CertiRocq";
        rev = "6d34b50bfea92aece62712ae120890c9fda8e514";
        hash = "sha256-7NVJcNfX/q59iDA7/Y0cb8CsgP5E1iddqW/Emk4f9mE=";
      };

      # CertiRocq itself: built from upstream's own overlay
      # (.nix/coq-overlays/CertiRocq/default.nix) rather than nixpkgs'
      # rocqPackages_9_1.CertiRocq. nixpkgs' recipe is a snapshot of an older
      # directory layout (top-level plugin/ and cplugin/, built with `make
      # plugins`); this fork has since moved those under plugins/ and split
      # the build into `make plugin` / `make cplugin`
      # (CertiRocq/certirocq@fb1cf3e), which breaks nixpkgs' buildPhase with
      # "make: *** plugin: No such file or directory". Building from
      # upstream's own overlay keeps the recipe in sync with the fork instead
      # of hand-patching a stale one.
      CertiRocq =
        (rocqPackages.callPackage "${certirocqSrc}/.nix/coq-overlays/CertiRocq/default.nix" {
          inherit pkgs;
        }).overrideAttrs
          (old: {
            version = "unstable-6d34b50b";
            src = certirocqSrc;
            # Both of these are cosmetic fixups of what the generic
            # mkCoqDerivation machinery leaves behind when it can't resolve
            # `version` against a known release (there is none here — see
            # certirocqSrc above): a "-broken" name suffix and meta.broken.
            name = "coq9.1-CertiRocq-unstable-6d34b50b";
            meta = (old.meta or { }) // { broken = false; };
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
          base64
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
        inherit base64;
      };

      # The proofs are checked by building, so building is the test suite.
      checks.${system}.build = authentikate-wasm;

      devShells.${system}.default = pkgs.mkShell {
        name = "authentikate";
        packages = [
          rocqPackages.rocq-core
          rocqPackages.coq
          CertiRocq
          base64
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
