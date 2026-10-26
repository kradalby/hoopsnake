{
  self,
  inputs,
  ...
}: {
  perSystem = {
    pkgs,
    system,
    ...
  }: let
    keys = pkgs.runCommand "hoopsnake-test-keys" {nativeBuildInputs = [pkgs.openssh];} ''
      mkdir -p $out
      for name in host client rejected; do
        ssh-keygen -N "" -t ed25519 -f "$out/$name"
      done
      (printf 'alice-boot '; cat "$out/host.pub") > "$out/known_hosts"
    '';
    policy = sshUsers:
      pkgs.writeText "policy.json" (builtins.toJSON {
        tagOwners."tag:hoopsnake" = ["owner@"];
        acls = [
          {
            action = "accept";
            src = sshUsers;
            dst = ["tag:hoopsnake:22"];
          }
          {
            action = "accept";
            src = ["bob@" "relay@"];
            dst = ["tag:hoopsnake:9021"];
          }
        ];
      });
    allow = policy ["bob@" "relay@"];
    deny = policy ["bob@"];
    peer = {
      imports = [inputs.headscale.nixosModules.testkit-peer];
      environment.systemPackages = [pkgs.openssh pkgs.curl pkgs.netcat-openbsd];
      environment.etc = {
        "client-key" = {
          source = "${keys}/client";
          mode = "0600";
        };
        "rejected-key" = {
          source = "${keys}/rejected";
          mode = "0600";
        };
      };
    };
  in {
    checks = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
      hoopsnake-systemd = pkgs.testers.runNixOSTest {
        name = "hoopsnake-systemd-initrd-stage1";
        nodes = {
          headscale = {
            imports = [inputs.headscale.nixosModules.testkit];
            services.headscale.settings.node.ephemeral.inactivity_timeout = "70s";
            environment.systemPackages = [pkgs.jq];
          };
          bob = peer;
          relay = {
            imports = [peer];
            systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
          };
          alice = {
            config,
            lib,
            ...
          }: let
            unlock = pkgs.writeShellApplication {
              name = "unlock";
              text = ''
                IFS= read -r input
                test "$input" = unlock-input
                touch /tmp/unlocked
                echo hoopsnake-unlock
              '';
            };
          in {
            imports = [self.nixosModules.default];
            virtualisation = {
              useBootLoader = true;
              useEFIBoot = true;
              cores = 2;
              memorySize = 1024;
            };
            boot.loader.systemd-boot.enable = true;
            boot.loader.efi.canTouchEfiVariables = true;
            boot.kernelParams = ["ip=${config.networking.primaryIPAddress}:::255.255.255.0::eth1:off"];
            boot.initrd.network = {
              enable = true;
              udhcpc.enable = false;
              hoopsnake = {
                enable = true;
                ssh.authorizedKeysFile = "${keys}/client.pub";
                ssh.commandLine = ["/bin/unlock"];
                systemd-credentials = {
                  privateHostKey = {
                    file = "${keys}/host";
                    encrypted = false;
                  };
                  clientId = {
                    text = "disabled";
                    encrypted = false;
                  };
                  clientSecret = {
                    text = "disabled";
                    encrypted = false;
                  };
                };
                tailscale = {
                  name = "alice-boot";
                  tags = ["tag:hoopsnake"];
                  tsnetVerbose = true;
                };
              };
            };
            boot.initrd.secrets."/etc/hosts" = config.environment.etc.hosts.source;
            testing.initrdBackdoor = true;
            boot.initrd.systemd = {
              enable = true;
              initrdBin = [unlock];
              services.hoopsnake = {
                # The driver supplies a runtime key before starting the real module's unit.
                wantedBy = lib.mkForce [];
                environment.TS_NO_LOGS_NO_SUPPORT = "1";
                serviceConfig.EnvironmentFile = "/run/hoopsnake.env";
              };
            };
          };
        };
        testScript = ''
          import json
          import shlex

          def nodes():
              return json.loads(headscale.succeed("headscale nodes list -o json"))

          def identity():
              matches = [n for n in nodes() if n["givenName"] == "alice-boot"]
              assert len(matches) == 1, matches
              return matches[0]

          def ssh(ip, key="client"):
              return (
                  "printf 'unlock-input\\n' | timeout 15 ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes "
                  "-o ConnectTimeout=5 -o StrictHostKeyChecking=yes "
                  "-o HostKeyAlias=alice-boot -o UserKnownHostsFile=${keys}/known_hosts "
                  f"-i /etc/{key}-key -T arbitrary@{ip} ignored-command"
              )

          with subtest("Runtime control and peer registration"):
              headscale.start()
              for peer, user in [(bob, "bob"), (relay, "relay")]:
                  peer.start()
                  key = headscale.succeed(f"hs-authkey {user}").strip()
                  peer.succeed(f"hs-join {shlex.quote(key)}")
              headscale.succeed("headscale policy set -f ${allow}")
              key = headscale.succeed("hs-authkey owner --ephemeral --tags tag:hoopsnake").strip()
              alice.start()
              alice.wait_for_unit("initrd.target")
              alice.succeed("printf '%s\\n' " + shlex.quote("TS_AUTHKEY=" + key) +
                            " TS_BASE_URL=http://headscale > /run/hoopsnake.env")
              alice.succeed("systemctl start hoopsnake")
              bob.wait_until_succeeds("tailscale ping --c=1 alice-boot", timeout=120)
              first = identity()
              assert "tag:hoopsnake" in first["tags"], first
              assert first["preAuthKey"]["ephemeral"], first
              ip = first["ipAddresses"][0]

          with subtest("SSH key denial has an allowed control"):
              alice.fail("test -e /tmp/unlocked")
              status, output = bob.execute(ssh(ip, "rejected") + " 2>&1")
              assert status == 255 and "Permission denied (publickey)" in output, (status, output)
              alice.fail("test -e /tmp/unlocked")
              output = bob.succeed(ssh(ip))
              assert "hoopsnake-unlock" in output, output
              alice.succeed("test -e /tmp/unlocked")

          with subtest("Direct SSH without DERP and forced-DERP SSH"):
              bob.wait_until_succeeds(
                  rf"tailscale ping --c=3 {ip} | grep -E 'via (\[[0-9a-f:]+\]|[0-9.]+):[0-9]+'", timeout=60)
              headscale.succeed("systemctl stop headscale")
              try:
                  assert "hoopsnake-unlock" in bob.succeed(ssh(ip))
              finally:
                  headscale.succeed("systemctl start headscale")
              headscale.succeed("HEADSCALE_CLI_TIMEOUT=60s headscale health")
              relay.wait_until_succeeds(
                  f"tailscale ping --c=1 --until-direct=false {ip} | grep 'via DERP(headscale)'", timeout=120)
              assert "hoopsnake-unlock" in relay.succeed(ssh(ip))
              # The underlay must not expose the application listener.
              bob.fail("nc -z -w 3 alice 22")

          with subtest("Tailnet ACL denial preserves allowed metrics and SSH"):
              headscale.succeed("headscale policy set -f ${deny}")
              relay.wait_until_succeeds(f"! nc -z -w 3 {ip} 22", timeout=60)
              alice.succeed("rm /tmp/unlocked")
              status, output = relay.execute(ssh(ip) + " 2>&1")
              assert status != 0 and "hoopsnake-unlock" not in output, (status, output)
              alice.fail("test -e /tmp/unlocked")
              relay.succeed(f"curl -fsS --max-time 10 http://{ip}:9021/metrics | grep hoopsnake_running")
              assert "hoopsnake-unlock" in bob.succeed(ssh(ip))

          with subtest("Restart creates a fresh ephemeral identity"):
              alice.succeed("systemctl stop hoopsnake")
              headscale.wait_until_succeeds(
                  "headscale nodes list -o json | jq -e 'all(.[]; .givenName != \"alice-boot\")'", timeout=180)
              alice.succeed("systemctl start hoopsnake")
              bob.wait_until_succeeds("tailscale ping --c=1 alice-boot", timeout=120)
              second = identity()
              assert second["nodeKey"] != first["nodeKey"], (first, second)
              assert "tag:hoopsnake" in second["tags"], second
              assert "hoopsnake-unlock" in bob.succeed(ssh(second["ipAddresses"][0]))

          with subtest("Authenticated unlock and shutdown complete boot"):
              alice.succeed("test -e /tmp/unlocked")
              alice.switch_root()
              alice.wait_for_unit("multi-user.target", timeout=90)
              headscale.wait_until_succeeds(
                  "headscale nodes list -o json | jq -e 'all(.[]; .givenName != \"alice-boot\")'", timeout=180)
        '';
      };
      configtest = pkgs.testers.runNixOSTest {
        name = "hoopsnake-configtest";
        nodes = {
          headscale.imports = [inputs.headscale.nixosModules.testkit];
          bob.environment.systemPackages = [self.packages.${system}.hoopsnake];
        };
        testScript = ''
          import shlex
          start_all()
          key = headscale.succeed("hs-authkey config --ephemeral").strip()
          command = (
              "env TS_NO_LOGS_NO_SUPPORT=1 TS_BASE_URL=http://headscale TS_AUTHKEY=" + shlex.quote(key) +
              " timeout --kill-after=5 45 hoopsnake -configtest -name config -tags tag:hoopsnake -stateDir /tmp/config /bin/true 2>&1"
          )
          with subtest("Packaged configtest registers with a runtime auth key"):
              assert "Configuration tested ok" in bob.succeed(command, timeout=120)
        '';
      };
    };
  };
}
