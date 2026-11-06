package kmsbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/evidencevault"
	"github.com/SemperSupra/evidence-service/pkg/transitclient"
)

// persistentReceipt contains only a public verification key and a bundle
// locator. The independent signing private key is never persisted.
type persistentReceipt struct {
	Bundle    string `json:"bundle"`
	PublicKey string `json:"public_key"`
}

func persistedFixture() map[evidencevault.Kind][]byte {
	return map[evidencevault.Kind][]byte{
		evidencevault.EncryptedCapture:  []byte("OWNED-TEST-PERSISTED-ENCRYPTED-PCAP"),
		evidencevault.DecryptedEvidence: []byte("OWNED-TEST-PERSISTED-DERIVED-STREAM"),
		evidencevault.TLSKeyLog:         []byte("OWNED-TEST-PERSISTED-EPHEMERAL-KEYLOG"),
	}
}

// TestPersistentOpenBaoRestart is called twice in separate Go processes, on
// either side of an actual OpenBao server/container restart. This test MUST
// run only on the disposable public-runner localhost fixture.
func TestPersistentOpenBaoRestart(t *testing.T) {
	phase := os.Getenv("OPENBAO_PERSIST_PHASE")
	if phase == "" {
		t.Skip("persistent OpenBao fixture not configured")
	}
	if phase != "seal" && phase != "recover" {
		t.Fatal("unrecognized persistence phase")
	}
	if os.Getenv("OPENBAO_TEST_ADDR") != "http://127.0.0.1:8200" {
		t.Fatal("persistent test requires isolated loopback OpenBao")
	}
	root := os.Getenv("OPENBAO_PERSIST_ROOT")
	if root == "" || !filepath.IsAbs(root) {
		t.Fatal("absolute disposable test directory required")
	}
	token := os.Getenv("OPENBAO_TEST_TOKEN")
	if token == "" {
		t.Fatal("test-only restricted Transit token required")
	}
	wrapper, err := transitclient.New("http://127.0.0.1:8200", "transit", "evidence-test", token, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	records := filepath.Join(root, "records")
	receiptPath := filepath.Join(root, "public-recovery.json")
	switch phase {
	case "seal":
		if err := os.MkdirAll(records, 0700); err != nil {
			t.Fatal(err)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := Seal(ctx, records, "owned-restart-test", persistedFixture(), wrapper, "isolated-test-signer", private)
		if err != nil {
			t.Fatal(err)
		}
		record, err := json.Marshal(persistentReceipt{
			Bundle: bundle, PublicKey: base64.StdEncoding.EncodeToString(public),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(receiptPath, record, 0600); err != nil {
			t.Fatal(err)
		}
		if stat, err := os.Stat(receiptPath); err != nil || stat.Mode().Perm() != 0600 {
			t.Fatal("public recovery record must be private on runner")
		}
	case "recover":
		raw, err := os.ReadFile(receiptPath)
		if err != nil {
			t.Fatal(err)
		}
		var record persistentReceipt
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(record.Bundle) != records {
			t.Fatal("recovery bundle escaped fixture directory")
		}
		key, err := base64.StdEncoding.DecodeString(record.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Fatal("invalid out-of-bundle trusted test key")
		}
		for kind, expected := range persistedFixture() {
			actual, err := Open(ctx, record.Bundle, kind, wrapper, "isolated-test-signer", ed25519.PublicKey(key))
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("post-restart %s recovery failed: %v", kind, err)
			}
		}
		if _, err := Open(ctx, record.Bundle, evidencevault.TLSKeyLog, wrapper, "wrong-signer", ed25519.PublicKey(key)); !errors.Is(err, errors.New("untrusted KMS binding")) && err == nil {
			t.Fatal("incorrect signer accepted after recovery")
		}
	}
}
