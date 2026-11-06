package kmsbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/evidencevault"
	"github.com/SemperSupra/evidence-service/pkg/transitclient"
)

// TestLiveKMSBundle is an opt-in isolated public-runner test. It uses only
// freshly created, synthetic evidence and an ephemeral localhost OpenBao.
func TestLiveKMSBundle(t *testing.T) {
	addr := os.Getenv("OPENBAO_TEST_ADDR")
	token := os.Getenv("OPENBAO_TEST_TOKEN")
	admin := os.Getenv("OPENBAO_TEST_ADMIN_TOKEN")
	if addr == "" && token == "" && admin == "" {
		t.Skip("requires isolated OpenBao synthetic test fixture")
	}
	if addr != "http://127.0.0.1:8200" || token == "" || admin == "" {
		t.Fatal("only fully configured isolated loopback OpenBao is admitted")
	}
	transit, err := transitclient.New(addr, "transit", "evidence-test", token, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := filepath.Join(t.TempDir(), "restricted")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	synthetic := map[evidencevault.Kind][]byte{
		evidencevault.EncryptedCapture:  []byte("OWNED-TEST-ORIGINAL-ENCRYPTED-PCAP"),
		evidencevault.DecryptedEvidence: []byte("OWNED-TEST-DECODED-APPLICATION-STREAM"),
		evidencevault.TLSKeyLog:         []byte("OWNED-TEST-DISPOSABLE-TLS-KEYLOG"),
	}
	bundle, err := Seal(ctx, root, "owned-live-kms-bundle", synthetic, transit, "independent-test-signer", private)
	if err != nil {
		t.Fatalf("full signed bundle + real Transit sealing failed: %v", err)
	}
	verify := func(stage string) {
		t.Helper()
		for kind, want := range synthetic {
			got, err := Open(ctx, bundle, kind, transit, "independent-test-signer", public)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s recovery of %s failed: %v", stage, kind, err)
			}
		}
	}
	verify("initial")
	if _, err := Open(ctx, bundle, evidencevault.TLSKeyLog, transit, "untrusted-signer", public); err == nil {
		t.Fatal("real KMS path accepted untrusted signer")
	}

	// Rotate the isolated root-managed Transit key, not the worker token.
	// The pre-rotation signed bundle must remain recoverable afterwards.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+"/v1/transit/keys/evidence-test/rotate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", admin)
	h := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := h.Do(req)
	if err != nil {
		t.Fatal("isolated Transit rotation request failed")
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("isolated Transit key rotation denied (status %d)", resp.StatusCode)
	}
	verify("after-rotation")

	// Another signed bundle from the same signer must not be substituted.
	other, err := Seal(ctx, root, "owned-other-session", synthetic, transit, "independent-test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	from := filepath.Join(other, "kms-envelope.json")
	to := filepath.Join(bundle, "kms-envelope.json")
	forged, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, bundle, evidencevault.TLSKeyLog, transit, "independent-test-signer", public); err == nil {
		t.Fatal("cross-session signed KMS envelope substitution accepted")
	}
}
