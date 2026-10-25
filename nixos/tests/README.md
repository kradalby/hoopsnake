# Headscale integration tests

Run on Linux with `/dev/kvm`, using the repository's pinned inputs:

```sh
nix build \
  .#checks.x86_64-linux.hoopsnake-systemd \
  .#checks.x86_64-linux.configtest -L --no-link
go test ./...
golangci-lint run ./...
nix fmt -- --check .
```

The Headscale input keeps its own nixpkgs because its server needs a newer Go
compiler. Its exported `testkit` and `testkit-peer` modules provide runtime
keys, control at `http://headscale`, and an isolated, self-signed test DERP.
There is no database snapshot, nginx proxy, or application TLS certificate.
Hoopsnake is a Go tsnet client; Rust-only insecure feature flags do not apply.

`hoopsnake-systemd` boots the real NixOS module in a systemd EFI initrd. The
backdoor supplies a runtime auth key before starting the module's unit. It
checks SSH public-key and password-auth rejection before a successful unlock, host-key checking,
input delivery and terminal mode for PTY and non-PTY execution, fixed-command execution regardless of SSH username
or requested command, and removal of the auth key from the child environment.
Direct UDP and forced-DERP paths must each carry successful SSH traffic.
Direct SSH must survive a control/DERP outage, and relay SSH must recover when
Headscale returns.
SSH and metrics also run over tailnet IPv6.
A restrictive network policy denies relay SSH while preserving relay metrics
and direct-peer SSH, so an outage cannot satisfy the denial test. Metrics must
record both successful and failed SSH authentication. The underlay cannot
reach port 22. Restart and switch-root exercise ephemeral identity lifecycle
and completion of boot. The configured command writes an unlock marker; the
fixture does not create an encrypted disk or test LUKS key handling.

`configtest` exercises the packaged binary as an unprivileged user with
`CAP_NET_ADMIN`, needed by tsnet to choose the VLAN on a multihomed VM. Initrd
itself deliberately retains the real module's root privileges, needed for
unlocking disks. Missing credentials and invalid auth keys cannot pass the
configuration check. Invalid-key failure requires Headscale's explicit rejection
and a successful valid-key registration immediately afterward. Registration runs
with a bounded process timeout because
`Run` deliberately detaches tsnet startup from its cancellation context.

Hoopsnake does not use WhoIs, application grants, Tailscale SSH policy, Serve,
Funnel, or application HTTPS. It uses ordinary tailnet TCP filtering plus its
own SSH public-key authorization. State is deliberately held in memory; a
restart creates a fresh identity instead of recovering a persistent node.
With `TS_AUTHKEY`, key capabilities and tags come from the supplied key;
`-tags`, `-preauthorized`, and `-deleteExisting` apply to the minting path.

The Go tests also exercise real SSH handshakes with omitted, empty and populated
authorized-key lists. Only a configured key may authenticate. Credential tests
require unused API/OAuth secrets to be removed before child commands can run.

The pinned Headscale implements OAuth and device management, but rejects
Hoopsnake's legacy `device` scope. The VM test proves that the same credentials
can obtain a token without that scope, then asserts the application's
`invalid_scope` failure. Successful OAuth minting and application-driven stale
node cleanup therefore remain incompatible with this fixture. `tailscale_test.go` uses a local
HTTP contract fixture to check the requested `device` scope, credentials,
ephemeral/tagged non-reusable key request, both preauthorization and cleanup
opt-in states, stale matching-node
selection, preservation of connected, undated, recent and differently named nodes, and error
propagation from token, key, list and delete endpoints. A separate test proves
that an explicit auth key bypasses both minting and cleanup. These tests do
not prove cloud-side OAuth scope enforcement or real Tailscale API-key access;
those require a disposable Tailscale cloud tailnet and credentials. Headscale
also accepts but ignores `preauthorized`, so cloud device approval remains
outside this fixture. The API-key path ignores `TS_BASE_URL` and targets the
Tailscale cloud; these tests never send it a credential.
