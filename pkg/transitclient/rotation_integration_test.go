package transitclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveOpenBaoRotation is restricted to the ephemeral owned localhost
// fixture. It never contacts external or production OpenBao instances.
func TestLiveOpenBaoRotation(t *testing.T) {
	addr, scoped, admin := os.Getenv("OPENBAO_TEST_ADDR"), os.Getenv("OPENBAO_TEST_TOKEN"), os.Getenv("OPENBAO_TEST_ADMIN_TOKEN")
	if addr == "" && scoped == "" && admin == "" {
		t.Skip("requires isolated synthetic OpenBao fixture")
	}
	if addr != "http://127.0.0.1:8200" || scoped == "" || admin == "" {
		t.Fatal("isolated loopback fixture with both scoped and administrator tokens required")
	}
	c, err := New(addr, "transit", "evidence-test", scoped, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	scope := []byte("owned-test-session/rotation/capture")
	before, err := c.WrapKey(ctx, dek, scope)
	if err != nil || !strings.HasPrefix(before, "vault:v1:") {
		t.Fatalf("initial isolated Transit version not v1: %v", err)
	}

	rotateURL := addr + "/v1/transit/keys/evidence-test/rotate"
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	rotate := func(token string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rotateURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal("isolated rotation request failed")
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if status := rotate(scoped); status != http.StatusForbidden {
		t.Fatalf("scoped worker unexpectedly permitted key rotation (status %d)", status)
	}
	if status := rotate(admin); status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("isolated administrator rotation rejected (status %d)", status)
	}

	// Old ciphertext must remain recoverable after version 2 is created.
	oldKey, err := c.UnwrapKey(ctx, before, scope)
	if err != nil || !bytes.Equal(oldKey, dek) {
		t.Fatalf("previous Transit key version lost its synthetic data: %v", err)
	}
	after, err := c.RewrapKey(ctx, before, scope)
	if err != nil || !strings.HasPrefix(after, "vault:v2:") || after == before {
		t.Fatalf("rewrap did not advance to version 2: %v", err)
	}
	recovered, err := c.UnwrapKey(ctx, after, scope)
	if err != nil || !bytes.Equal(recovered, dek) {
		t.Fatalf("rewrapped synthetic key not recoverable: %v", err)
	}
	if _, err := c.UnwrapKey(ctx, after, []byte("owned-test-session/rotation/foreign-capture")); err == nil {
		t.Fatal("rotated ciphertext decrypted under wrong derivation context")
	}
}
