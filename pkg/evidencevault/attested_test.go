package evidencevault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAttestedSyntheticRoundTrip(t *testing.T) {
	parent, artifacts, kek := fixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, manifest, receipt, err := SealAttested(parent, "owned-attested", artifacts, kek, "owned-test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SignerID != "owned-test-signer" || manifest.SessionID != "owned-attested" {
		t.Fatal("incorrect attested bundle identities")
	}
	for kind, expected := range artifacts {
		plain, err := OpenAttested(bundle, kind, kek, "owned-test-signer", public)
		if err != nil || !bytes.Equal(plain, expected) {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	files, err := os.ReadDir(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 8 {
		t.Fatalf("expected original 7 files and independent receipt, got %d", len(files))
	}
	if st, err := os.Stat(filepath.Join(bundle, "attestation.json")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("attestation file must be private 0600")
	}
	stages, _ := filepath.Glob(filepath.Join(parent, ".attestation-stage-*"))
	if len(stages) != 0 {
		t.Fatal("staging directories leaked")
	}
}

func TestAttestedRejectsForgedAuthenticatedManifest(t *testing.T) {
	parent, artifacts, kek := fixture(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	bundle, _, _, err := SealAttested(parent, "owned-test", artifacts, kek, "test-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bundle, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// Attacker who obtained the *wrapping* key can authenticate a forged
	// manifest HMAC but does not possess the independent signing key.
	entry := m.Entries[DecryptedEvidence]
	entry.PlainBytes++
	m.Entries[DecryptedEvidence] = entry
	mac, err := authManifest(m, kek)
	if err != nil {
		t.Fatal(err)
	}
	m.MAC = mac
	forged, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(forged, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	// Legacy single-artifact recovery accepts unrelated forged manifest
	// metadata, proving the independent receipt adds a distinct safeguard.
	if _, err := OpenArtifact(bundle, TLSKeyLog, kek); err != nil {
		t.Fatalf("fixture must retain a separately valid TLS artifact: %v", err)
	}
	if _, err := OpenAttested(bundle, TLSKeyLog, kek, "test-signer", public); err == nil {
		t.Fatal("attestation accepted manifest re-authenticated using compromised KEK")
	}
}

func TestAttestedRejectsMissingAndUntrustedReceipt(t *testing.T) {
	parent, artifacts, kek := fixture(t)
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	bundle, _, _, err := SealAttested(parent, "owned-test", artifacts, kek, "first-signer", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAttested(bundle, TLSKeyLog, kek, "other-signer", pub); err == nil {
		t.Fatal("caller-selected signer substitution accepted")
	}
	if _, err := OpenAttested(bundle, TLSKeyLog, kek, "first-signer", wrong); err == nil {
		t.Fatal("untrusted signing key accepted")
	}
	receiptFile := filepath.Join(bundle, "attestation.json")
	if err := os.Remove(receiptFile); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAttested(bundle, TLSKeyLog, kek, "first-signer", pub); err == nil {
		t.Fatal("unsigned evidence recovery accepted")
	}
	if err := os.Symlink("manifest.json", receiptFile); err == nil {
		if _, err := OpenAttested(bundle, TLSKeyLog, kek, "first-signer", pub); err == nil {
			t.Fatal("symlinked receipt accepted")
		}
	}
}

func TestSealAttestedInvalidSignerDoesNotPublish(t *testing.T) {
	parent, artifacts, kek := fixture(t)
	if _, _, _, err := SealAttested(parent, "owned-test", artifacts, kek, "", nil); err == nil {
		t.Fatal("accepted missing signing authority")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid signing key wrote a bundle")
	}
}
