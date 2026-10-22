{
  description = "An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.fenix = {
    url = "github:nix-community/fenix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.rocq-base64 = {
    url = "github:womeier/rocq-base64";
    flake = false;
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      rocq-base64,
    }:
    let
      # Build the portable Wasm artifacts on Linux; Darwin only builds the host.
      system = "x86_64-linux";
      lib = nixpkgs.lib;

      pkgs = import nixpkgs {
        inherit system;
        # CertiRocq depends on CompCert (unfree) for its Clight backend.
        config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "compcert" ];
      };

      mkRustToolchain =
        system:
        with fenix.packages.${system};
        combine [
          (stable.withComponents [
            "cargo"
            "rustc"
            "rust-std"
            "rustfmt"
            "clippy"
            "rust-analyzer"
            "rust-src"
          ])
          targets.wasm32-unknown-unknown.stable.rust-std
        ];

      rustToolchain = mkRustToolchain system;

      jco = pkgs.buildNpmPackage {
        pname = "authentikate-component-test-tools";
        version = "1.39.0";
        src = lib.fileset.toSource {
          root = ./tests;
          fileset = lib.fileset.unions [
            ./tests/package.json
            ./tests/package-lock.json
          ];
        };
        npmDepsHash = "sha256-YqhhpvR5/S8jYytyeC9cib+50nog9H6JytAUxkyIKeQ=";
        dontNpmBuild = true;
        npmFlags = [ "--ignore-scripts" ];
        nativeBuildInputs = [ pkgs.makeWrapper ];
        installPhase = ''
          runHook preInstall
          mkdir -p $out/lib $out/bin
          cp -r node_modules $out/lib/
          makeWrapper ${pkgs.nodejs}/bin/node $out/bin/jco \
            --add-flags $out/lib/node_modules/@bytecodealliance/jco/dist/jco.js
          runHook postInstall
        '';
      };

      # One Rocq 9.1 toolchain.
      # Two dependencies are different:
      #   * WasmCert (nixpkgs' coq-wasm) 2.2.1 instead of 2.2.0.
      #   * MetaRocq from its "9.1" development branch instead of the 1.5.1-9.1
      #     release.  CertiRocq has needed that branch since
      #     https://github.com/CertiRocq/certirocq/pull/158, and its own
      #     .nix/config.nix pins `metarocq.override.version = "9.1"`
      #     accordingly; the fork's config.nix says the same.
      rocqPackages = pkgs.rocqPackages_9_1.overrideScope (
        _self: super:
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
        }
      );

      base64 =
        (rocqPackages.callPackage "${rocq-base64}/.nix/rocq-overlays/base64/default.nix" { }).overrideAttrs
          (old: {
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
            meta = (old.meta or { }) // {
              broken = false;
            };
          });

      # Rocq sources and the build driver.  Keeps build products and editor
      # leftovers out of the derivation.
      src = lib.cleanSourceWith {
        src = ./.;
        filter =
          path: type:
          let
            relative = lib.removePrefix "${toString ./.}/" (toString path);
          in
          lib.elem relative [
            "Makefile"
            "components/service/Makefile"
            "components/service/_RocqProject"
          ]
          ||
            builtins.any
              (
                directory:
                (relative == directory || lib.hasPrefix "${directory}/" relative)
                && (
                  type == "directory"
                  || builtins.any (suffix: lib.hasSuffix suffix path) [
                    ".v"
                    ".mjs"
                    ".wat"
                    ".wit"
                  ]
                )
              )
              [
                "components/service"
                "components/crypto/wit"
                "components/email/wit"
                "tests"
              ]
          || (
            type == "directory"
            && lib.elem relative [
              "components"
              "components/crypto"
              "components/email"
            ]
          );
      };

      # The service as a single Wasm module, compiled by CertiRocq from
      # components/service/theories/extraction.v, wrapped with canonical component interfaces.
      authentikate-wasm = pkgs.stdenv.mkDerivation {
        pname = "authentikate-wasm";
        version = "0.1.0";
        inherit src;

        nativeBuildInputs = [
          rocqPackages.coq
          CertiRocq
          base64
          pkgs.nodejs
          pkgs.wasm-tools
          pkgs.binaryen
        ];

        COQBIN = "${rocqPackages.coq}/bin/";

        buildPhase = ''
          runHook preBuild
          ulimit -s unlimited 2>/dev/null || true
          make -C components/service -j $NIX_BUILD_CORES
          runHook postBuild
        '';

        doCheck = true;
        checkPhase = ''
          runHook preCheck
          node tests/ffi-adapters.mjs
          node tests/component.mjs
          runHook postCheck
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out
          cp build/authentikate.component.wasm build/authentikate.core.wasm $out/
          runHook postInstall
        '';

        meta = {
          description = "An authentication backend in Rocq, compiled to WebAssembly by CertiRocq";
          license = lib.licenses.mit;
          platforms = [ system ];
        };
      };

      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };

      hostSrc = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./Cargo.toml
          ./Cargo.lock
          ./Makefile
          ./host
          ./components/crypto
          ./components/email
          ./components/gateway
          ./components/service/wit
        ];
      };

      # Cache this Linux-built output for all hosts, including macOS.
      authentikate-host-component = rustPlatform.buildRustPackage {
        pname = "authentikate-host-component";
        version = "0.1.0";
        src = hostSrc;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [
          pkgs.wasm-tools
          pkgs.wac-cli
        ];
        buildPhase = ''
          runHook preBuild
          mkdir -p build
          cp ${authentikate-wasm}/authentikate.component.wasm build/
          make check-wit crypto-components email-stdout-component gateway-component compose-host
          runHook postBuild
        '';
        doCheck = false;
        installPhase = ''
          runHook preInstall
          mkdir -p $out
          cp build/host.component.wasm $out/
          runHook postInstall
        '';
      };

      mkLocal =
        pkgs:
        let
          hostRustPlatform = pkgs.makeRustPlatform {
            cargo = mkRustToolchain pkgs.stdenv.hostPlatform.system;
            rustc = mkRustToolchain pkgs.stdenv.hostPlatform.system;
          };
        in
        hostRustPlatform.buildRustPackage {
          pname = "authentikate-local";
          version = "0.1.0";
          src = hostSrc;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "-p"
            "authentikate-host"
          ];
          cargoTestFlags = [
            "-p"
            "authentikate-host"
          ];
          nativeBuildInputs = [
            pkgs.makeWrapper
          ];

          preBuild = ''
            mkdir -p build
            cp ${authentikate-host-component}/host.component.wasm build/
          '';

          postInstall = ''
            mkdir -p $out/share/authentikate
            cp build/host.component.wasm $out/share/authentikate/
            makeWrapper $out/bin/authentikate-host $out/bin/authentikate-local \
              --set HOST_COMPONENT $out/share/authentikate/host.component.wasm
          '';

          meta = {
            description = "Local authentication demo with in-memory accounts and stdout email";
            mainProgram = "authentikate-local";
            license = lib.licenses.mit;
            platforms = [
              system
              "aarch64-darwin"
            ];
          };
        };

      authentikate-local = mkLocal pkgs;
      darwinPackages = lib.genAttrs [ "aarch64-darwin" ] (system: {
        authentikate-local = mkLocal (import nixpkgs { inherit system; });
      });

      authentikate-production = pkgs.writeShellScriptBin "authentikate-production" ''
        echo "not yet supported"
      '';

      # Fetch only the pinned bundle resources used by this report, not the
      # multi-gigabyte full bundle. Update the hash when adding TeX dependencies.
      reportResources =
        pkgs.runCommand "authentikate-report-tex-resources"
          {
            nativeBuildInputs = [
              pkgs.tectonic
              pkgs.cacert
            ];
            outputHashMode = "recursive";
            outputHashAlgo = "sha256";
            outputHash = "sha256-A6IQgto0hd31t7xZBUmopdk0KHwqVAAyjpwMbq97h3I=";
          }
          ''
            export HOME=$TMPDIR/home
            mkdir -p "$HOME" work
            cp -r ${./report}/. work/
            cd work
            tectonic --bundle ${pkgs.tectonic.unwrapped.TECTONIC_BUNDLE_LOCKED} main.tex
            mkdir -p $out
            cp -r "$HOME/.cache/tectonic/bundles" $out/
          '';

      report = pkgs.stdenvNoCC.mkDerivation {
        pname = "authentikate-report";
        version = "0.1.0";
        src = ./report;
        nativeBuildInputs = [ pkgs.tectonic ];
        buildPhase = ''
          runHook preBuild
          export HOME=$TMPDIR/home
          mkdir -p "$HOME/.cache/tectonic"
          cp -r ${reportResources}/bundles "$HOME/.cache/tectonic/"
          chmod -R u+w "$HOME"
          tectonic --only-cached --bundle ${pkgs.tectonic.unwrapped.TECTONIC_BUNDLE_LOCKED} main.tex
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out
          cp main.pdf $out/
          runHook postInstall
        '';
      };
    in
    {
      packages = darwinPackages // {
        ${system} = {
          default = authentikate-wasm;
          inherit authentikate-wasm;
          inherit authentikate-local authentikate-production;
          inherit authentikate-host-component;
          # The heavy prebuilt dependency, exposed so CI can fetch it
          # substitute-only before building anything:
          #   nix build --max-jobs 0 .#CertiRocq
          # (It substitutes from womeier.cachix.org when the store path
          # matches; otherwise it rebuilds from the fork.)
          inherit CertiRocq;
          inherit base64;
          inherit jco;
          rust-toolchain = rustToolchain;
          inherit report;
        };
      };

      apps =
        (lib.mapAttrs (_: packages: {
          authentikate-local = {
            type = "app";
            program = lib.getExe packages.authentikate-local;
          };
        }) darwinPackages)
        // {
          ${system} = {
            authentikate-local = {
              type = "app";
              program = lib.getExe authentikate-local;
            };
            authentikate-production = {
              type = "app";
              program = lib.getExe authentikate-production;
            };
          };
        };

      # The proofs are checked by building, so building is the test suite.
      checks.${system}.build = authentikate-wasm;

      devShells.${system} = {
        default = pkgs.mkShell {
          name = "authentikate";
          packages = [
            rocqPackages.rocq-core
            rocqPackages.coq
            CertiRocq
            base64
            rocqPackages.stdlib
            rocqPackages.coq-lsp
            pkgs.gnumake
            pkgs.curl
            pkgs.python3

            # Service assembly and component regression tests use Node.
            pkgs.nodejs
            jco

            # The crypto primitives come from a Rust library, linked in through
            # the module's imports.
            # Fenix includes matching native/Wasm standard libraries and rust-lld.
            rustToolchain

            # To look at what came out, and to inspect the module's imports.
            pkgs.wasm-tools
            pkgs.wac-cli
            pkgs.binaryen

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

        report = pkgs.mkShell {
          name = "authentikate-report";
          packages = [ pkgs.tectonic ];
        };
      };
    };
}
