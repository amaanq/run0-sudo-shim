{
  description = "a shim imitating sudo, but using run0 in the background";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix-github-actions = {
      url = "github:nix-community/nix-github-actions";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      nix-github-actions,
      treefmt-nix,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      cargo-toml = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
      inherit (cargo-toml) name;

      build-pkg =
        pkgs:
        let
          inherit (pkgs) lib;
        in
        pkgs.rustPlatform.buildRustPackage {
          inherit name;
          inherit (cargo-toml) version;
          src = lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;

          postInstall = ''
            ln -s $out/bin/${name} $out/bin/sudo
            ln -s $out/bin/${name} $out/bin/sudoedit
          '';

          meta = {
            inherit (cargo-toml) description;
            mainProgram = name;
            license = lib.getLicenseFromSpdxId cargo-toml.license;
            maintainers = with lib.maintainers; [ grimmauld ];
          };
        };

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          ${name} = build-pkg pkgs;
          default = self.packages.${system}.${name};
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.rust-analyzer
            ];
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
        in
        treefmtEval.config.build.wrapper
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
        in
        {
          formatting = treefmtEval.config.build.check self;
          vm = pkgs.testers.runNixOSTest {
            name = "run0-sudo-shim-vm-test";
            nodes.machine = {
              imports = [ self.nixosModules.default ];
              security.polkit.persistentAuthentication = true;
              security.run0-sudo-shim.enable = true;

              users.users = {
                admin = {
                  isNormalUser = true;
                  extraGroups = [ "wheel" ];
                };
                noadmin = {
                  isNormalUser = true;
                };
              };
            };
            testScript = ''
              # machine.succeed('su - admin -c "sudo -v"') # can't yet give password, needs hacks to never ask for password in the test or enter the password
              machine.fail('su - noadmin -c "sudo -v"')
            '';
          };
        }
        // self.packages.${system}
      );

      githubActions = nix-github-actions.lib.mkGithubMatrix {
        checks = nixpkgs.lib.getAttrs [ "x86_64-linux" ] self.checks;
      };

      overlays.default = final: prev: { ${name} = build-pkg prev; };

      nixosModules.default =
        {
          pkgs,
          lib,
          config,
          ...
        }:
        let
          cfg = config.security.run0-sudo-shim;
        in
        {
          options.security = {
            polkit.persistentAuthentication = lib.mkEnableOption "patch polkit to allow persistent authentication and add rules";
            run0-sudo-shim = {
              enable = lib.mkEnableOption "enable run0-sudo-shim instead of sudo";
              package = lib.mkPackageOption pkgs "run0-sudo-shim" { } // {
                # should be removed when upstreaming to nixpkgs
                default = pkgs.run0-sudo-shim or build-pkg pkgs;
              };
            };
          };

          config = lib.mkMerge [
            (lib.mkIf cfg.enable {
              environment.systemPackages = [ cfg.package ];
              security.sudo.enable = false;
              security.polkit.enable = true;

              # https://github.com/NixOS/nixpkgs/pull/419588
              security.pam.services.systemd-run0 = {
                setLoginUid = true;
                pamMount = false;
              };
            })
            (lib.mkIf config.security.polkit.persistentAuthentication {
              security.polkit.extraConfig = ''
                polkit.addRule(function(action, subject) {
                  if (action.id == "org.freedesktop.policykit.exec") {
                    return polkit.Result.AUTH_ADMIN_KEEP;
                  }
                });

                polkit.addRule(function(action, subject) {
                  if (action.id.indexOf("org.freedesktop.systemd1.") == 0) {
                    return polkit.Result.AUTH_ADMIN_KEEP;
                  }
                });
              '';

              # don't apply patch starting version 127, where persistent auth is supported upstream
              security.polkit.package = lib.mkIf (lib.versionOlder pkgs.polkit.version "127") (
                pkgs.polkit.overrideAttrs (old: {
                  patches = old.patches or [ ] ++ [
                    (pkgs.fetchpatch {
                      url = "https://github.com/polkit-org/polkit/pull/533.patch?full_index=1";
                      hash = "sha256-i8RkHDGdSwO6/kueVhMVefqUqC38lQmEBSKtminDlN8=";
                    })
                  ];
                })
              );
            })
          ];
        };
    };
}
