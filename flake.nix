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
        # The go.mod minimum (1.27.1) is newer than nixpkgs' default go.
        airbag = pkgs.buildGo127Module rec {
          pname = "airbag";
          version = "0.1.0-dev";
          src = pkgs.lib.cleanSource ./.;
          vendorHash = "sha256-Ek0AUKLb/49k6YaO2osZ6pSL5M05tdKLSeCHSWzWVoI=";
          subPackages = [ "cmd/airbag" ];
          env.CGO_ENABLED = 0;
          # airbag version prints this, as for a release: v0.1.0-dev.
          ldflags = [ "-s" "-w" "-X main.version=v${version}" ];
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
            go test ./internal/... ./creds ./operation ./outbox ./policy ./proxy ./githubpr
            runHook postCheck
          '';
          installPhase = "mkdir -p $out";
        });
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go_1_27 pkgs.gopls pkgs.git pkgs.python3 pkgs.diffutils ];
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-rfc-style);
    };
}
