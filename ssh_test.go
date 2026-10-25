package hoopsnake

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh"
)

func TestSSHRequiresAuthorizedKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, configuration := range []string{"omitted", "empty", "configured"} {
		t.Run(configuration, func(t *testing.T) {
			s := &TailnetSSH{}
			if configuration != "omitted" {
				var keys []byte
				if configuration == "configured" {
					keys = ssh.MarshalAuthorizedKey(signer.PublicKey())
				}
				file := filepath.Join(t.TempDir(), "authorized_keys")
				if err := os.WriteFile(file, keys, 0600); err != nil {
					t.Fatal(err)
				}
				s.authorizedKeyFiles = paths{file}
			}
			if err := s.setupAuthorizedKeys(); err != nil {
				t.Fatal(err)
			}
			s.AddHostKey(signer)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = s.Serve(listener)
			}()
			t.Cleanup(func() {
				s.Close()
				<-done
			})
			for _, authenticate := range []bool{false, true} {
				config := &ssh.ClientConfig{
					User:            "arbitrary",
					HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
					Timeout:         5 * time.Second,
				}
				if authenticate {
					config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
				}
				client, err := ssh.Dial("tcp", listener.Addr().String(), config)
				if err == nil {
					client.Close()
				}
				allowed := configuration == "configured" && authenticate
				if (err == nil) != allowed {
					t.Errorf("authenticate=%v: allowed=%v, error=%v", authenticate, allowed, err)
				}
			}
		})
	}
}

func serveTestSSH(t *testing.T, s *TailnetSSH, signer ssh.Signer) string {
	t.Helper()
	s.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(listener)
	}()
	t.Cleanup(func() {
		s.Close()
		<-done
	})
	return listener.Addr().String()
}

func TestSSHCommandResult(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOOPSNAKE_TEST_ENV", "preserved")
	for _, name := range []string{"TS_AUTHKEY", "TS_API_KEY", "TS_API_CLIENT_ID", "TS_API_CLIENT_SECRET"} {
		t.Setenv(name, "secret")
	}
	if _, err := (&TailnetSSH{stateDir: t.TempDir()}).tsnetServer(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tty := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			command []string
			status  int
			output  string
		}{
			{"environment", []string{shell, "-c", `test "$HOOPSNAKE_TEST_ENV" = preserved && test -z "${TS_AUTHKEY+x}${TS_API_KEY+x}${TS_API_CLIENT_ID+x}${TS_API_CLIENT_SECRET+x}" && printf command-ok`}, 0, "command-ok"},
			{"exit", []string{shell, "-c", "exit 7"}, 7, ""},
			{"start", []string{filepath.Join(t.TempDir(), "missing-command")}, 1, ""},
			{"signal", []string{shell, "-c", "kill -TERM $$"}, 143, ""},
		} {
			t.Run(fmt.Sprintf("%s/pty=%v", tc.name, tty), func(t *testing.T) {
				s := &TailnetSSH{command: tc.command}
				s.Handler = s.handle
				s.authorizedPubKeys = append(s.authorizedPubKeys, signer.PublicKey())
				s.PublicKeyHandler = s.validatePubkey
				client, err := ssh.Dial("tcp", serveTestSSH(t, s, signer), &ssh.ClientConfig{
					User: "arbitrary", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
					HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				if tty {
					if err := session.RequestPty("xterm", 24, 80, nil); err != nil {
						t.Fatal(err)
					}
				}
				output, err := session.CombinedOutput("ignored-command")
				status := 0
				if err != nil {
					var exitError *ssh.ExitError
					if !errors.As(err, &exitError) {
						t.Fatal(err)
					}
					status = exitError.ExitStatus()
				}
				if status != tc.status || string(output) != tc.output {
					t.Fatalf("command returned status %d, output %q; want status %d, output %q", status, output, tc.status, tc.output)
				}
			})
		}
	}
}

func TestSSHAuthenticationMetricsBounded(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	s := &TailnetSSH{}
	s.authorizedPubKeys = append(s.authorizedPubKeys, signer.PublicKey())
	s.PublicKeyHandler = s.validatePubkey
	address := serveTestSSH(t, s, signer)
	for i := range 4 {
		key := signer
		if i != 0 {
			_, privateKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			key, err = ssh.NewSignerFromKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
		}
		client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
			User: fmt.Sprintf("user-%d", i), Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
			HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second,
		})
		if err == nil {
			client.Close()
		}
		if (err == nil) != (i == 0) {
			t.Fatalf("user-%d authentication: %v", i, err)
		}
	}
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, metric := range metrics {
		if metric.GetName() == "hoopsnake_authentications" {
			if count := len(metric.Metric); count != 2 {
				t.Fatalf("authentication series count = %d, want 2 outcomes regardless of supplied identities", count)
			}
			return
		}
	}
	t.Fatal("authentication metric missing")
}
