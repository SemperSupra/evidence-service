package transitclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

// TestLiveOpenBaoTransit is opt-in and uses only an ephemeral isolated OpenBao
// dev server, a restricted synthetic token and fresh test-only key material.
// It is skipped in ordinary unit tests and never contacts a production vault.
func TestLiveOpenBaoTransit(t *testing.T) {
	addr, token := os.Getenv("OPENBAO_TEST_ADDR"), os.Getenv("OPENBAO_TEST_TOKEN")
	if addr == "" && token == "" {
		t.Skip("requires isolated synthetic OpenBao fixture")
	}
	if addr == "" || token == "" {
		t.Fatal("incomplete OpenBao integration fixture")
	}
	client, err := New(addr, "transit", "evidence-test", token, nil)
	if err != nil {
		t.Fatal(err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	scope := []byte("owned-synthetic-session/pcapng/dek")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	wrapped, err := client.WrapKey(ctx, dek, scope)
	if err != nil {
		t.Fatalf("real Transit wrap failed: %v", err)
	}
	recovered, err := client.UnwrapKey(ctx, wrapped, scope)
	if err != nil || !bytes.Equal(dek, recovered) {
		t.Fatalf("real Transit unwrap failed: %v", err)
	}
	if _, err := client.UnwrapKey(ctx, wrapped, []byte("different-session/pcapng/dek")); err == nil {
		t.Fatal("cross-session scope decrypted with the wrong derived key")
	}
	rewrapped, err := client.RewrapKey(ctx, wrapped, scope)
	if err != nil {
		t.Fatalf("real Transit rewrap failed: %v", err)
	}
	recoveredAfterRewrap, err := client.UnwrapKey(ctx, rewrapped, scope)
	if err != nil || !bytes.Equal(dek, recoveredAfterRewrap) {
		t.Fatalf("real Transit rewrapped key not recoverable: %v", err)
	}
	if _, err := client.call(ctx, "keys", map[string]string{}); err == nil {
		t.Fatal("restricted Transit token allowed key management")
	}
	for i := range dek {
		dek[i] = 0
	}
}
