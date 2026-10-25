package hoopsnake

import (
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
