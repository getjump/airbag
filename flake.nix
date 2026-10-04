{
  description = "airbag: run a coding agent in a copy-on-write branch of your machine, review one diff, apply or discard";

  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        airbag = pkgs.buildGoModule {
          pname = "airbag";
          version = "0.1.0-dev";
          src = pkgs.lib.cleanSource ./.;
          vendorHash = "sha256-cXg1ad6JfXgR2Ot8JUHvOumstEGrhLEvCkKEVZu4pJo=";
          subPackages = [ "cmd/airbag" ];
          env.CGO_ENABLED = 0;
          ldflags = [ "-s" "-w" ];
          # Unit tests run in checks.unit; the sandbox ones need user
          # namespaces and FUSE, which the build sandbox does not give.
          doCheck = false;
          meta = {
            description = "Local sandbox for coding agents: approve outcomes, not commands";
            homepage = "https://github.com/getjump/airbag";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "airbag";
            # macOS: the native prototype (docs/macos.md).
            platforms = pkgs.lib.platforms.linux ++ pkgs.lib.platforms.darwin;
          };
        };
        default = airbag;
      });

      checks = forAll (pkgs: {
        build = self.packages.${pkgs.system}.airbag;
        # Go unit tests that need nothing but a build sandbox.
        unit = self.packages.${pkgs.system}.airbag.overrideAttrs (old: {
          pname = "airbag-unit";
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            go test ./internal/...
            runHook postCheck
          '';
          installPhase = "mkdir -p $out";
        });
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.gopls pkgs.git pkgs.python3 pkgs.diffutils ];
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-rfc-style);
    };
}
