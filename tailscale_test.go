package hoopsnake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/v2"
)

// These tests isolate request construction and cleanup from control-plane policy.
// The VM tests separately check Headscale compatibility, not cloud authorization.
func TestOAuthAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, failure                 string
		preauthorized, deleteExisting bool
	}{
		{name: "defaults"},
		{name: "preauthorized", preauthorized: true},
		{name: "cleanup", deleteExisting: true},
		{name: "all", preauthorized: true, deleteExisting: true},
		{name: "oauth failure", failure: "oauth", preauthorized: true, deleteExisting: true},
		{name: "mint failure", failure: "mint", preauthorized: true, deleteExisting: true},
		{name: "list failure", failure: "list", preauthorized: true, deleteExisting: true},
		{name: "delete failure", failure: "delete", preauthorized: true, deleteExisting: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"TS_AUTHKEY", "TS_API_KEY", "TS_API_CLIENT_ID", "TS_API_CLIENT_SECRET"} {
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			var deleted []string
			minted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				stage := map[string]string{
					"/api/v2/oauth/token":       "oauth",
					"/api/v2/tailnet/-/keys":    "mint",
					"/api/v2/tailnet/-/devices": "list",
					"/api/v2/device/stale":      "delete",
				}[r.URL.Path]
				if stage == "" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				if stage == "oauth" {
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					id, secret, _ := r.BasicAuth()
					if id == "" {
						id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
					}
					if id != "client" || secret != "secret" || r.Form.Get("scope") != "device" || r.Form.Get("grant_type") != "client_credentials" {
						t.Errorf("unexpected OAuth request: %v", r.Form)
					}
				} else if r.Header.Get("Authorization") != "Bearer token" {
					t.Error("missing bearer token")
				}
				if (stage == "list" || stage == "delete") && !tc.deleteExisting {
					t.Error("cleanup requested while disabled")
				}
				if stage == tc.failure {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"message":"denied","error":"access_denied"}`)
					return
				}
				switch stage {
				case "oauth":
					fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer","expires_in":3600}`)
				case "mint":
					if r.Method != http.MethodPost {
						t.Errorf("mint method: %s", r.Method)
					}
					var request tailscale.CreateKeyRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					create := request.Capabilities.Devices.Create
					if !create.Ephemeral || create.Preauthorized != tc.preauthorized || create.Reusable || !reflect.DeepEqual(create.Tags, []string{"tag:hoopsnake"}) {
						t.Errorf("key capabilities: %+v", create)
					}
					minted = true
					fmt.Fprint(w, `{"key":"auth-key"}`)
				case "list":
					if !minted {
						t.Error("cleanup before mint succeeded")
					}
					if r.Method != http.MethodGet || r.URL.Query().Get("fields") != "all" {
						t.Errorf("list request: %s %s", r.Method, r.URL)
					}
					old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
					recent := time.Now().UTC().Format(time.RFC3339)
					fmt.Fprintf(w, `{"devices":[
                        {"id":"online","hostname":"boot","connectedToControl":true,"lastSeen":null},
                        {"id":"unknown","hostname":"boot","lastSeen":null},
                        {"id":"connected","hostname":"boot","connectedToControl":true,"lastSeen":%q},
                        {"id":"stale","hostname":"boot","lastSeen":%q},
                        {"id":"recent","hostname":"boot","lastSeen":%q},
                        {"id":"other","hostname":"other","lastSeen":%q}
                    ]}`, old, old, recent, old)
				case "delete":
					if r.Method != http.MethodDelete {
						t.Errorf("delete method: %s", r.Method)
					}
					deleted = append(deleted, "stale")
					fmt.Fprint(w, `{}`)
				}
			}))
			defer server.Close()
			t.Setenv("TS_BASE_URL", server.URL)
			dir := t.TempDir()
			for name, value := range map[string]string{"id": "client\n", "secret": " secret\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := &TailnetSSH{serviceName: "boot", stateDir: dir, tags: []string{"tag:hoopsnake"}, preauthorized: tc.preauthorized, deleteExisting: tc.deleteExisting, maxNodeAge: time.Minute, clientIDFile: filepath.Join(dir, "id"), clientSecretFile: filepath.Join(dir, "secret")}
			srv, err := s.tsnetServer(context.Background())
			if tc.failure != "" {
				if err == nil || srv != nil {
					t.Fatalf("%s: server=%v error=%v", tc.failure, srv, err)
				}
				if !strings.Contains(err.Error(), "denied") {
					t.Fatalf("lost API error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !srv.Ephemeral || srv.AuthKey != "auth-key" || srv.ControlURL != server.URL {
				t.Fatalf("server: %+v", srv)
			}
			var wantDeleted []string
			if tc.deleteExisting {
				wantDeleted = []string{"stale"}
			}
			if !reflect.DeepEqual(deleted, wantDeleted) {
				t.Fatalf("deleted %v", deleted)
			}
		})
	}
}

func TestAuthKeyBypassesMintAndCleanup(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "provided-key")
	t.Setenv("TS_API_KEY", "unused-api-key")
	t.Setenv("TS_API_CLIENT_ID", "unused-client")
	t.Setenv("TS_API_CLIENT_SECRET", "unused-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("authkey must bypass OAuth and cleanup: %s", r.URL)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("TS_BASE_URL", server.URL)
	s := &TailnetSSH{serviceName: "boot", stateDir: t.TempDir(), deleteExisting: true, clientIDFile: "missing", clientSecretFile: "missing"}
	srv, err := s.tsnetServer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if srv.AuthKey != "provided-key" || !srv.Ephemeral {
		t.Fatalf("server: %+v", srv)
	}
	for _, name := range []string{"TS_AUTHKEY", "TS_API_KEY", "TS_API_CLIENT_ID", "TS_API_CLIENT_SECRET"} {
		if _, exists := os.LookupEnv(name); exists {
			t.Errorf("%s remains in child environment", name)
		}
	}
}

func TestFailedAPIKeyMintClearsCredentials(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "")
	if err := os.Unsetenv("TS_AUTHKEY"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_API_KEY", "api-key")
	t.Setenv("TS_API_CLIENT_ID", "unused-client")
	t.Setenv("TS_API_CLIENT_SECRET", "unused-secret")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&TailnetSSH{}).tsnetServer(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mint with cancelled context: %v", err)
	}
	for _, name := range []string{"TS_API_KEY", "TS_API_CLIENT_ID", "TS_API_CLIENT_SECRET"} {
		if _, exists := os.LookupEnv(name); exists {
			t.Errorf("%s remains in child environment", name)
		}
	}
}

func TestOAuthEnvironmentCredentials(t *testing.T) {
	t.Setenv("TS_API_KEY", "")
	if err := os.Unsetenv("TS_API_KEY"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_API_CLIENT_ID", "client")
	t.Setenv("TS_API_CLIENT_SECRET", "secret")
	t.Setenv("TS_BASE_URL", "http://headscale")
	client, err := (&TailnetSSH{}).setupTSClient()
	if err != nil {
		t.Fatal(err)
	}
	auth, ok := client.Auth.(*tailscale.OAuth)
	if !ok || auth.ClientID != "client" || auth.ClientSecret != "secret" || !reflect.DeepEqual(auth.Scopes, []string{"device"}) {
		t.Fatalf("OAuth: %#v", client.Auth)
	}
	if client.BaseURL.String() != "http://headscale" {
		t.Fatalf("control URL: %s", client.BaseURL)
	}
	for _, name := range []string{"TS_API_CLIENT_ID", "TS_API_CLIENT_SECRET"} {
		if _, exists := os.LookupEnv(name); exists {
			t.Errorf("%s remains in child environment", name)
		}
	}
	if _, err := (&TailnetSSH{}).setupTSClient(); err != ErrNoAPIKeys {
		t.Fatalf("missing credentials: %v", err)
	}
}

func TestAPIKeyPrecedesOAuth(t *testing.T) {
	t.Setenv("TS_API_KEY", "api-key")
	s := &TailnetSSH{clientIDFile: "missing", clientSecretFile: "missing"}
	client, err := s.setupTSClient()
	if err != nil {
		t.Fatal(err)
	}
	if client.APIKey != "api-key" || client.Tailnet != "-" {
		t.Fatalf("client: %+v", client)
	}
	if _, exists := os.LookupEnv("TS_API_KEY"); exists {
		t.Fatal("API key remains in child environment")
	}
}
