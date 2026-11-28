{
  description = "An authentication backend written in Rocq, compiled to WebAssembly by CertiRocq";

  # Upstream nixpkgs, pinned: rocqPackages.base64 (rocq-base64, including its
  # MetaRocq bytestring bridge) is in master since NixOS/nixpkgs@5406e3b4 but
  # has not reached nixos-unstable yet, so this pins that commit rather than
  # the channel branch.  Its tree is otherwise identical to the womeier fork
  # this input used to track, so the rest of the toolchain is unchanged.
  # Once base64 reaches nixos-unstable, this can become
  # "github:NixOS/nixpkgs/nixos-unstable".
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5406e3b4f49d1be515fe38edc0f29b414d8ac664";
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

      # One Rocq 9.2 toolchain, with MetaRocq's matching development branch
      # pinned by revision and WasmCert 2.2.1.
      rocqPackages = pkgs.rocqPackages_9_2.overrideScope (
        _self: super:
        let
          wasmcert = super.wasmcert.override { version = "2.2.1"; };
          # nixpkgs' base64 picks its default version from a (rocq,
          # metarocq-utils) table that wants metarocq-utils >= 1.4; MetaRocq is
          # overridden below to its "9.2" development branch, whose version
          # string ("unstable-...") fails that test and leaves base64 with no
          # default version.  0.1.1 is the release the table would select.
          base64 = super.base64.override { version = "0.1.1"; };
          metarocq = super.metarocq.override {
            version = {
              version = "unstable-0231b430";
              location = {
                rev = "0231b430258a9702f258c37e9b55fd896c88c92e";
                hash = "sha256-hDN+Zj7UJT55eVHv6zP/XlI9fZ1O/vdI7Gavbkj3Oaw=";
              };
            };
          };
          # nixpkgs only selects VsRocq through Rocq 9.1. Pin the newer
          # release and use its current OCaml dependencies (no GTK frontend).
          vsrocq-language-server =
            (super.vsrocq-language-server.override {
              version = {
                version = "2.5.1";
                location = {
                  rev = "v2.5.1";
                  hash = "sha256-4s0L0JHUR7u5wvhexIG7SduJlq4LKejjX2bkIipvNXw=";
                };
              };
            }).overrideAttrs (
              _:
              let
                ocamlPackages = _self.rocq-core.ocamlPackages;
                # nixpkgs' 0.2.1 predates OCaml 5 support; 0.3.0 supports
                # OCaml >= 5.3, including this toolchain's OCaml 5.5.
                memprofLimits = ocamlPackages.buildDunePackage {
                  pname = "memprof-limits";
                  version = "0.3.0";
                  src = pkgs.fetchFromGitLab {
                    owner = "gadmm";
                    repo = "memprof-limits";
                    rev = "v0.3.0";
                    hash = "sha256-k/uB1jDQtE/PkVPU8zg8cpOmlPttTWVpKerQ0HuWfuI=";
                  };
                  nativeBuildInputs = [ ocamlPackages.cppo ];
                  meta.license = lib.licenses.lgpl3;
                };
              in
              {
                buildInputs = [
                  _self.coq
                  _self.rocq-core
                ] ++ (with ocamlPackages; [
                  findlib
                  yojson
                  jsonrpc
                  ppx_blob
                  ppx_inline_test
                  ppx_assert
                  ppx_sexp_conv
                  ppx_deriving
                  ppx_import
                  sexplib
                  ppx_yojson_conv
                  lsp
                  sel
                  ppx_optcomp
                  result
                ]) ++ [ memprofLimits ];
              }
            );
        in
        {
          inherit base64 wasmcert metarocq vsrocq-language-server;
        }
      );

      # Upstream rocq-9.2 plus the rebased Wasm foreign-call import extension,
      # required by the service's registered provider primitives. Pin the port
      # and use its upstream Rocq 9.2 build recipe. Foreign calls remain outside
      # the backend correctness proof (see PLAN.md).
      certirocqSrc = pkgs.fetchFromGitHub {
        owner = "womeier-bot";
        repo = "certirocq";
        rev = "015a9b36d307fe51ba72aa6643dd560dd6e9320e";
        hash = "sha256-d18joJJN7MqdZSYLwgyUFEOzqItxphu6zIehKe9Em44=";
      };

      # Use the upstream Rocq 9.2 overlay, which builds and installs with Dune.
      CertiRocq =
        (rocqPackages.callPackage "${certirocqSrc}/.nix/rocq-overlays/CertiRocq/default.nix" {
          inherit pkgs;
        }).overrideAttrs
          (old: {
            version = "unstable-015a9b36";
            src = certirocqSrc;
            # Both of these are cosmetic fixups of what the generic
            # mkCoqDerivation machinery leaves behind when it can't resolve
            # `version` against a known release (there is none here — see
            # certirocqSrc above): a "-broken" name suffix and meta.broken.
            name = "rocq9.2-CertiRocq-unstable-015a9b36";
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
          rocqPackages.base64
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
      mkAppComponent =
        live:
        rustPlatform.buildRustPackage {
          pname = if live then "authentikate-live-component" else "authentikate-app-component";
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
            make check-wit crypto-components email-${if live then "smtp" else "stdout"}-component ${
              if live then "compose-live-app" else "compose-app"
            }
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

      authentikate-app-component = mkAppComponent false;
      authentikate-live-component = mkAppComponent true;

      mkLocal =
        pkgs: live:
        pkgs.writeShellApplication {
          name = if live then "authentikate-live" else "authentikate-local";
          runtimeInputs = [
            pkgs.coreutils
            pkgs.openssl
          ];
          text = ''
            config_dir="''${CONFIG_DIR:-./run/config}"
            accounts_dir="''${ACCOUNTS_DIR:-./run/accounts}"
            ${lib.optionalString live ''
              if [[ ! -f "$config_dir/config.json" || ! -f "$config_dir/signing.key" ]]; then
                echo "Provision $config_dir with config.json, signing.key, and a deliverable service.email_from before starting live delivery." >&2
                echo "You can initialize the default directories with nix run .#authentikate-local first." >&2
                exit 1
              fi
            ''}
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
              -S cli=y,inherit-network=${if live then "y" else "n"},allow-ip-name-lookup=n,tcp=${if live then "y" else "n"},udp=n,inherit-env=n \
              -W fuel=2000000000${lib.optionalString live ",timeout=90s"} \
              -W max-memory-size=134217728 \
              -W max-memories=8 \
              -W max-instances=32 \
              -W max-tables=16 \
              -W max-wasm-stack=8388608,async-stack-size=16777216 \
              ${
                if live then
                  "${authentikate-live-component}/app-live.component.wasm"
                else
                  "${authentikate-app-component}/app.component.wasm"
              }
          '';
          meta = {
            description =
              if live then
                "Authentication demo sending email through localhost SMTP"
              else
                "Local authentication demo using stock Wasmtime";
            license = lib.licenses.mit;
          };
        };

      authentikate-local = mkLocal pkgs false;
      authentikate-live = mkLocal pkgs true;
      darwinPackages = lib.genAttrs [ "aarch64-darwin" ] (system: {
        authentikate-local = mkLocal (import nixpkgs { inherit system; }) false;
        authentikate-live = mkLocal (import nixpkgs { inherit system; }) true;
        authentikate = mkLocal (import nixpkgs { inherit system; }) false;
      });

    in
    {
      packages = darwinPackages // {
        ${system} = {
          default = authentikate-wasm;
          inherit authentikate-wasm;
          inherit
            authentikate-local
            authentikate-app-component
            authentikate-live
            authentikate-live-component
            ;
          wasmtime = pkgs.wasmtime;
          authentikate = authentikate-local;
          # The heavy prebuilt dependency, exposed so CI can fetch it
          # substitute-only before building anything:
          #   nix build --max-jobs 0 .#CertiRocq
          # (It substitutes from womeier.cachix.org when the store path
          # matches; otherwise it rebuilds from the fork.)
          inherit CertiRocq;
          inherit jco;
          vsrocq-language-server = rocqPackages.vsrocq-language-server;
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
          authentikate-live = {
            type = "app";
            program = lib.getExe packages.authentikate-live;
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
            authentikate-live = {
              type = "app";
              program = lib.getExe authentikate-live;
            };
          };
        };

      # The proofs are checked by building, so building is the test suite.
      checks.${system} = {
        build = authentikate-wasm;
        app =
          pkgs.runCommand "authentikate-http-tests"
            {
              nativeBuildInputs = [
                pkgs.nodejs
                pkgs.wasmtime
              ];
              WASMTIME = lib.getExe pkgs.wasmtime;
            }
            ''
              # Wasmtime caches compiled modules under $XDG_CACHE_HOME (or
              # $HOME/.cache); the sandbox's $HOME is unwritable, and running
              # the suite without the cache recompiles the component 25 times.
              export XDG_CACHE_HOME="$TMPDIR/cache"
              mkdir -p "$XDG_CACHE_HOME" tests
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
            rocqPackages.base64
            rocqPackages.stdlib
            rocqPackages.vsrocq-language-server
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
