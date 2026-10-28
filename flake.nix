{
  description = "An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq";

  # The womeier fork of nixpkgs: it carries the rocq-base64 packages
  # (rocqPackages.base64 and the MetaRocq bridge base64-bytestring), which
  # upstream nixpkgs does not have yet.
  inputs.nixpkgs.url = "github:womeier/nixpkgs";
  inputs.fenix = {
    url = "github:nix-community/fenix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
    }:
    let
      # Build the portable Wasm artifacts on Linux; Darwin uses the same component.
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
            "tests/ffi-adapters.mjs"
            "tests/component.mjs"
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
                # The configuration contract, staged into the
                # service's WIT tree by build.mjs.
                "wit"
              ]
          || (
            type == "directory"
            && lib.elem relative [
              "components"
              "components/crypto"
              "components/email"
              "tests"
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
          rocqPackages.base64-bytestring
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

      workspace = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace;
      rustSrc =
        files:
        lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions (
            [
              ./Cargo.toml
              ./Cargo.lock
            ]
            ++ map (member: ./. + "/${member}/Cargo.toml") workspace.members
            ++ files
          );
        };

      # Keep every workspace manifest for --locked resolution, but not unrelated
      # implementations. Cargo still needs a target for each unused member.
      rustPostPatch = lib.concatMapStringsSep "\n" (member: ''
        if [ ! -d ${member}/src ]; then
          mkdir -p ${member}/src
          cp ${pkgs.writeText "empty-rust-target.rs" ""} ${member}/src/lib.rs
        fi
      '') workspace.members;

      # Cache this Linux-built output for all hosts, including macOS.
      authentikate-app-component = rustPlatform.buildRustPackage {
        pname = "authentikate-app-component";
        version = "0.1.0";
        src = rustSrc [
          ./Makefile
          ./composition.wac
          ./tests/app-interface.mjs
          ./components/config/build.rs
          ./components/config/src
          ./components/config/wit
          ./components/crypto
          ./components/email
          ./components/gateway
          ./components/storage
          ./components/service/wit
          ./wit
        ];
        postPatch = rustPostPatch;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [
          pkgs.wasm-tools
          pkgs.wac-cli
          pkgs.nodejs
        ];
        buildPhase = ''
          runHook preBuild
          mkdir -p build
          cp ${authentikate-wasm}/authentikate.component.wasm build/
          make check-wit crypto-components email-stdout-component compose-app
          runHook postBuild
        '';
        doCheck = false;
        installPhase = ''
          runHook preInstall
          mkdir -p $out
          cp build/*.component.wasm $out/
          runHook postInstall
        '';
      };

      mkLocal =
        pkgs:
        pkgs.writeShellApplication {
          name = "authentikate-local";
          runtimeInputs = [ pkgs.coreutils pkgs.openssl ];
          text = ''
            config_dir="''${CONFIG_DIR:-./run/config}"
            accounts_dir="''${ACCOUNTS_DIR:-./run/accounts}"
            umask 077
            if [[ -z "''${CONFIG_DIR:-}" && ! -e "$config_dir" && ! -L "$config_dir" ]]; then
              mkdir -p ./run
              mkdir -m 700 "$config_dir"
              cp ${./config.example.json} "$config_dir/config.json"
              (set -C; openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' > "$config_dir/signing.key")
            fi
            if [[ -z "''${ACCOUNTS_DIR:-}" ]]; then
              mkdir -p "$accounts_dir"
            fi
            if [[ ! -d "$config_dir" || ! -d "$accounts_dir" ]]; then
              echo "Provision CONFIG_DIR ($config_dir) and ACCOUNTS_DIR ($accounts_dir) before starting." >&2
              exit 1
            fi
            exec ${lib.getExe pkgs.wasmtime} serve \
              --addr 127.0.0.1:3000 \
              --dir "$config_dir::/config" \
              --dir "$accounts_dir::/accounts" \
              --max-instance-reuse-count 1 \
              --max-instance-concurrent-reuse-count 1 \
              --max-concurrent-requests 1 \
              --max-concurrent-connections 8 \
              --no-logging-prefix \
              -S cli=y,inherit-network=n,allow-ip-name-lookup=n,tcp=n,udp=n,inherit-env=n \
              -W fuel=2000000000 \
              -W max-memory-size=134217728 \
              -W max-memories=8 \
              -W max-instances=32 \
              -W max-tables=16 \
              -W max-wasm-stack=8388608,async-stack-size=16777216 \
              ${authentikate-app-component}/app.component.wasm
          '';
          meta = {
            description = "Local authentication demo using stock Wasmtime";
            license = lib.licenses.mit;
          };
        };

      authentikate-local = mkLocal pkgs;
      darwinPackages = lib.genAttrs [ "aarch64-darwin" ] (system: {
        authentikate-local = mkLocal (import nixpkgs { inherit system; });
        authentikate = mkLocal (import nixpkgs { inherit system; });
      });

    in
    {
      packages = darwinPackages // {
        ${system} = {
          default = authentikate-wasm;
          inherit authentikate-wasm;
          inherit authentikate-local authentikate-app-component;
          wasmtime = pkgs.wasmtime;
          authentikate = authentikate-local;
          # The heavy prebuilt dependency, exposed so CI can fetch it
          # substitute-only before building anything:
          #   nix build --max-jobs 0 .#CertiRocq
          # (It substitutes from womeier.cachix.org when the store path
          # matches; otherwise it rebuilds from the fork.)
          inherit CertiRocq;
          inherit jco;
          rust-toolchain = rustToolchain;
        };
      };

      apps =
        (lib.mapAttrs (_: packages: {
          authentikate = {
            type = "app";
            program = lib.getExe packages.authentikate;
          };
          authentikate-local = {
            type = "app";
            program = lib.getExe packages.authentikate-local;
          };
        }) darwinPackages)
        // {
          ${system} = {
            authentikate = {
              type = "app";
              program = lib.getExe authentikate-local;
            };
            authentikate-local = {
              type = "app";
              program = lib.getExe authentikate-local;
            };
          };
        };

      # The proofs are checked by building, so building is the test suite.
      checks.${system} = {
        build = authentikate-wasm;
        app = pkgs.runCommand "authentikate-http-tests"
          {
            nativeBuildInputs = [ pkgs.nodejs pkgs.wasmtime ];
            WASMTIME = lib.getExe pkgs.wasmtime;
          }
          ''
            mkdir -p tests
            cp ${./tests/http.mjs} tests/http.mjs
            mkdir -p build
            cp ${authentikate-app-component}/*.component.wasm build/
            node tests/http.mjs
            touch $out
          '';
      };

      devShells.${system} = {
        default = pkgs.mkShell {
          name = "authentikate";
          packages = [
            rocqPackages.rocq-core
            rocqPackages.coq
            CertiRocq
            rocqPackages.base64-bytestring
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
            pkgs.wasmtime
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
      };
    };
}
