package kmsbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/SemperSupra/evidence-service/pkg/evidencevault"
)

type testWrapper struct {
	key         []byte
	scope       []byte
	wrapCalls   int
	unwrapCalls int
	failWrap    bool
}

func (w *testWrapper) WrapKey(_ context.Context, key, scope []byte) (string, error) {
	w.wrapCalls++
	if w.failWrap || len(key) != 32 || len(scope) == 0 {
		return "", errors.New("synthetic wrapping refused")
	}
	w.key = bytes.Clone(key)
	w.scope = bytes.Clone(scope)
	return "vault:v1:owned-synthetic-test-key", nil
}

func (w *testWrapper) UnwrapKey(_ context.Context, ciphertext string, scope []byte) ([]byte, error) {
	w.unwrapCalls++
	if ciphertext != "vault:v1:owned-synthetic-test-key" || !bytes.Equal(scope, w.scope) {
		return nil, errors.New("synthetic scope mismatch")
	}
	return bytes.Clone(w.key), nil
}

func setup(t *testing.T) (string, map[evidencevault.Kind][]byte, *testWrapper, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "restricted")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	art := map[evidencevault.Kind][]byte{
		evidencevault.EncryptedCapture:  []byte("SYNTHETIC-ENCRYPTED-CAPTURE"),
		evidencevault.DecryptedEvidence: []byte("SYNTHETIC-DERIVED-APPLICATION-CONTENT"),
		evidencevault.TLSKeyLog:         []byte("SYNTHETIC-OWNED-TLS-TEST-ONLY-SECRET"),
	}
	return root, art, &testWrapper{}, pub, private
}

func TestSignedBundleKMSRecovery(t *testing.T) {
	root, art, wrapper, pub, private := setup(t)
	bundle, err := Seal(context.Background(), root, "owned-session", art, wrapper, "test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range art {
		got, err := Open(context.Background(), bundle, kind, wrapper, "test-signer", pub)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("recovery %s: %v", kind, err)
		}
	}
	if wrapper.wrapCalls != 1 || wrapper.unwrapCalls != len(art) {
		t.Fatal("incorrect number of KMS transactions")
	}
	entries, err := os.ReadDir(bundle)
	if err != nil || len(entries) != 9 {
		t.Fatalf("expected three pairs of ciphertexts, manifest and two signatures: %v", err)
	}
	for _, file := range entries {
		info, err := file.Info()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unrestricted evidence artifact %s", file.Name())
		}
		raw, err := os.ReadFile(filepath.Join(bundle, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, wrapper.key) {
			t.Fatal("raw test KEK stored beside evidence")
		}
	}
	stages, err := filepath.Glob(filepath.Join(root, ".kms-stage-*"))
	if err != nil || len(stages) != 0 {
		t.Fatal("abandoned staging directories")
	}
}

func TestTamperedEnvelopeFailsBeforeKMS(t *testing.T) {
	root, art, wrapper, pub, private := setup(t)
	bundle, err := Seal(context.Background(), root, "owned-session", art, wrapper, "test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bundle, "kms-envelope.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record Receipt
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Binding.WrappedKey = "vault:v1:attacker"
	forged, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), bundle, evidencevault.TLSKeyLog, wrapper, "test-signer", pub); err == nil {
		t.Fatal("forged binding accepted")
	}
	if wrapper.unwrapCalls != 0 {
		t.Fatal("untrusted envelope reached KMS")
	}
}

func TestWrongSignerAndAbsentEnvelopeFailClosed(t *testing.T) {
	root, art, wrapper, pub, private := setup(t)
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Seal(context.Background(), root, "owned-session", art, wrapper, "test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), bundle, evidencevault.TLSKeyLog, wrapper, "other-signer", pub); err == nil {
		t.Fatal("wrong signer accepted")
	}
	if _, err := Open(context.Background(), bundle, evidencevault.TLSKeyLog, wrapper, "test-signer", wrong); err == nil {
		t.Fatal("untrusted public key accepted")
	}
	path := filepath.Join(bundle, "kms-envelope.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), bundle, evidencevault.TLSKeyLog, wrapper, "test-signer", pub); err == nil {
		t.Fatal("missing wrapped-key envelope accepted")
	}
	if err := os.Symlink("manifest.json", path); err == nil {
		if _, err := Open(context.Background(), bundle, evidencevault.TLSKeyLog, wrapper, "test-signer", pub); err == nil {
			t.Fatal("symlinked envelope accepted")
		}
	}
	if wrapper.unwrapCalls != 0 {
		t.Fatal("failed signature/receipt checks invoked KMS")
	}
}

func TestNoPublicationAfterFailedKMSWrap(t *testing.T) {
	root, art, wrapper, _, private := setup(t)
	wrapper.failWrap = true
	if _, err := Seal(context.Background(), root, "owned-session", art, wrapper, "test-signer", private); err == nil {
		t.Fatal("failed KMS wrap published evidence")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed sealing left published or staged artifacts")
	}
}

func TestSignedManifestMutationFailsBeforeKMS(t *testing.T) {
	root, art, wrapper, pub, private := setup(t)
	bundle, err := Seal(context.Background(), root, "owned-session", art, wrapper, "test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bundle, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Even an otherwise valid JSON mutation changes the signed manifest digest.
	mutated := bytes.Replace(raw, []byte("owned-session"), []byte("other-session"), 1)
	if bytes.Equal(mutated, raw) {
		t.Fatal("test fixture missing session label")
	}
	if err := os.WriteFile(path, mutated, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), bundle, evidencevault.TLSKeyLog, wrapper, "test-signer", pub); err == nil {
		t.Fatal("manifest swap accepted")
	}
	if wrapper.unwrapCalls != 0 {
		t.Fatal("manifest mismatch reached KMS")
	}
}
