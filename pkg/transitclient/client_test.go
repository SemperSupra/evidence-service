package transitclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSyntheticWrapUnwrapRewrap(t *testing.T) {
	key := bytes.Repeat([]byte{0x35}, 32)
	scope := []byte("synthetic-session-1/tls_key_log")
	encodedScope := base64.StdEncoding.EncodeToString(scope)
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != "test-only-token" {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		var payload map[string]string
		if json.NewDecoder(r.Body).Decode(&payload) != nil || payload["context"] != encodedScope {
			http.Error(w, "wrong derivation context", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/transit/encrypt/evidence-test":
			b, err := base64.StdEncoding.DecodeString(payload["plaintext"])
			if err != nil || !bytes.Equal(b, key) {
				http.Error(w, "bad test DEK", http.StatusBadRequest)
				return
			}
			seen["encrypt"]++
			fmt.Fprint(w, `{"data":{"ciphertext":"vault:v1:synthetic"}}`)
		case "/v1/transit/decrypt/evidence-test":
			if payload["ciphertext"] != "vault:v1:synthetic" {
				http.Error(w, "wrong test ciphertext", http.StatusBadRequest)
				return
			}
			seen["decrypt"]++
			fmt.Fprintf(w, `{"data":{"plaintext":%q}}`, base64.StdEncoding.EncodeToString(key))
		case "/v1/transit/rewrap/evidence-test":
			if payload["ciphertext"] != "vault:v1:synthetic" {
				http.Error(w, "wrong rewrap input", http.StatusBadRequest)
				return
			}
			seen["rewrap"]++
			fmt.Fprint(w, `{"data":{"ciphertext":"vault:v2:synthetic"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "transit", "evidence-test", "test-only-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := c.WrapKey(context.Background(), key, scope)
	if err != nil || secret != "vault:v1:synthetic" {
		t.Fatalf("wrap: %v", err)
	}
	recovered, err := c.UnwrapKey(context.Background(), secret, scope)
	if err != nil || !bytes.Equal(recovered, key) {
		t.Fatalf("unwrap: %v", err)
	}
	rekeyed, err := c.RewrapKey(context.Background(), secret, scope)
	if err != nil || rekeyed != "vault:v2:synthetic" {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := c.UnwrapKey(context.Background(), secret, []byte("other-artifact")); err == nil {
		t.Fatal("cross-scope unwrap accepted by test server")
	}
	if seen["encrypt"] != 1 || seen["decrypt"] != 1 || seen["rewrap"] != 1 {
		t.Fatalf("unexpected operations: %+v", seen)
	}
}

func TestEndpointInputAndFailClosed(t *testing.T) {
	for _, base := range []string{"http://example.com", "http://localhost:8200", "https://vault.invalid/base", "https://user:pass@vault.invalid", "ftp://127.0.0.1"} {
		if _, err := New(base, "transit", "test", "test", nil); err == nil {
			t.Fatalf("accepted bad endpoint %s", base)
		}
	}
	if _, err := New("https://vault.invalid", "transit/../p", "test", "test", nil); err == nil {
		t.Fatal("accepted path injection")
	}
	if _, err := New("https://vault.invalid", "transit", "test", "", nil); err == nil {
		t.Fatal("accepted empty token")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://example.com/secret")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "transit", "test", "test-only-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WrapKey(context.Background(), make([]byte, 32), []byte("fixture")); err == nil {
		t.Fatal("redirect accepted")
	}
	if _, err := c.WrapKey(context.Background(), []byte("short"), []byte("fixture")); err == nil {
		t.Fatal("bad length accepted")
	}
	if _, err := c.RewrapKey(context.Background(), "not-vault-ciphertext", []byte("fixture")); err == nil {
		t.Fatal("bad ciphertext accepted")
	}
}

func TestErrorsDoNotExposeServerSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "DO_NOT_PRINT_THIS_TOKEN")
	}))
	defer srv.Close()
	c, err := New(srv.URL, "transit", "test", "test-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.WrapKey(context.Background(), make([]byte, 32), []byte("fixture"))
	if err == nil || strings.Contains(err.Error(), "DO_NOT_PRINT_THIS_TOKEN") || strings.Contains(err.Error(), "test-token") {
		t.Fatalf("error leaked or not rejected: %v", err)
	}
}
