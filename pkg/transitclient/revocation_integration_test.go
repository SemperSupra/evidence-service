package transitclient

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveOpenBaoWorkerRevocation runs LAST in the isolated dev-runner suite.
// It revokes only its freshly minted synthetic worker token, never a root
// token, production credential, or externally provisioned identity.
func TestLiveOpenBaoWorkerRevocation(t *testing.T) {
	address, worker := os.Getenv("OPENBAO_TEST_ADDR"), os.Getenv("OPENBAO_TEST_TOKEN")
	if address == "" && worker == "" {
		t.Skip("requires synthetic isolated OpenBao fixture")
	}
	if address != "http://127.0.0.1:8200" || worker == "" {
		t.Fatal("only owned disposable localhost worker token admitted")
	}
	client, err := New(address, "transit", "evidence-test", worker, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	scope := []byte("owned-revocation-test/session-a/pcap")
	wrapped, err := client.WrapKey(ctx, dek, scope)
	if err != nil {
		t.Fatalf("pre-revocation key wrapping failed: %v", err)
	}
	recovered, err := client.UnwrapKey(ctx, wrapped, scope)
	if err != nil || len(recovered) != 32 {
		t.Fatalf("pre-revocation recovery failed: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address+"/v1/auth/token/revoke-self", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", worker)
	httpClient := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal("isolated self-revocation request failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("isolated worker self-revocation rejected: %d", resp.StatusCode)
	}
	if _, err := client.UnwrapKey(ctx, wrapped, scope); err == nil ||
		strings.Contains(err.Error(), worker) || strings.Contains(err.Error(), wrapped) {
		t.Fatal("revoked worker recovered a key or leaked bearer material")
	}
	if _, err := client.WrapKey(ctx, dek, scope); err == nil ||
		strings.Contains(err.Error(), worker) {
		t.Fatal("revoked worker continued encrypting or leaked bearer")
	}
}
