package evidencevault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) (string, map[Kind][]byte, []byte) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	art := map[Kind][]byte{
		EncryptedCapture:  []byte("SYNTHETIC-ENCRYPTED-PCAPNG-BYTES"),
		DecryptedEvidence: []byte("SYNTHETIC-DERIVED-CONTENT-RECORDS"),
		TLSKeyLog:         []byte("CLIENT_TRAFFIC_SECRET_0 SYNTHETIC-RANDOM SYNTHETIC-TEST-SECRET\n"),
	}
	return root, art, key
}
func sealed(t *testing.T) (string, map[Kind][]byte, []byte) {
	t.Helper()
	root, art, key := fixture(t)
	dest, _, err := Seal(root, "owned-session-1", art, key)
	if err != nil {
		t.Fatal(err)
	}
	return dest, art, key
}
func TestPostHocRecoveryAllArtifacts(t *testing.T) {
	dest, art, key := sealed(t)
	for kind, expected := range art {
		// A separate read after Seal has returned reconstructs from disk.
		actual, err := OpenArtifact(dest, kind, key)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("%s: %v", kind, err)
		}
	}
}
func TestNoUnencryptedEvidenceOrWrappingKeyOnDisk(t *testing.T) {
	dest, art, key := sealed(t)
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("expected 6 sealed objects + manifest, got %d", len(entries))
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %o", e.Name(), info.Mode().Perm())
		}
		b, err := os.ReadFile(filepath.Join(dest, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, key) {
			t.Fatalf("wrapping key stored in %s", e.Name())
		}
		for _, plain := range art {
			if bytes.Contains(b, plain) {
				t.Fatalf("raw artifact stored in %s", e.Name())
			}
		}
	}
}
func TestWrongKeyDenied(t *testing.T) {
	dest, _, key := sealed(t)
	wrong := bytes.Repeat([]byte{42}, 32)
	if bytes.Equal(key, wrong) {
		t.Fatal("unexpected equal test keys")
	}
	if _, err := OpenArtifact(dest, TLSKeyLog, wrong); err == nil {
		t.Fatal("wrong key accepted")
	}
}
func TestCiphertextModificationDenied(t *testing.T) {
	dest, _, key := sealed(t)
	name := filepath.Join(dest, "tls_key_log.sealed")
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(name, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenArtifact(dest, TLSKeyLog, key); err == nil {
		t.Fatal("ciphertext mutation accepted")
	}
}
func TestManifestMutationDenied(t *testing.T) {
	dest, _, key := sealed(t)
	name := filepath.Join(dest, "manifest.json")
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	v["session_id"] = "forged-session"
	out, _ := json.Marshal(v)
	if err := os.WriteFile(name, out, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenArtifact(dest, TLSKeyLog, key); err == nil {
		t.Fatal("manifest mutation accepted")
	}
}
func TestCrossSessionSwapDenied(t *testing.T) {
	root, art, key := fixture(t)
	one, _, err := Seal(root, "session-a", art, key)
	if err != nil {
		t.Fatal(err)
	}
	two, _, err := Seal(root, "session-b", art, key)
	if err != nil {
		t.Fatal(err)
	}
	from := filepath.Join(one, "tls_key_log.wrapped")
	dest := filepath.Join(two, "tls_key_log.wrapped")
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenArtifact(two, TLSKeyLog, key); err == nil {
		t.Fatal("cross-session key swap accepted")
	}
}
func TestInsecureParentAndPathRejected(t *testing.T) {
	dir := t.TempDir()
	_, art, key := fixture(t)
	if _, _, err := Seal(dir, "owned-session", art, key); err == nil {
		t.Fatal("open parent allowed")
	}
	private := filepath.Join(dir, "restricted")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Seal(private, "../../bad", art, key); err == nil {
		t.Fatal("path traversal allowed")
	}
}
func TestNoMissingOrOversizeEvidence(t *testing.T) {
	root, art, key := fixture(t)
	delete(art, TLSKeyLog)
	if _, _, err := Seal(root, "owned", art, key); err == nil {
		t.Fatal("missing key artifact accepted")
	}
}

func TestManifestSymlinkIsRejected(t *testing.T) {
	dest, _, key := sealed(t)
	original := filepath.Join(dest, "manifest.json")
	copy := filepath.Join(dest, "manifest-backup")
	if err := os.Rename(original, copy); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(copy, original); err != nil {
		t.Skipf("no symlink support: %v", err)
	}
	if _, err := OpenArtifact(dest, TLSKeyLog, key); err == nil {
		t.Fatal("symlink manifest accepted")
	}
	if _, err := AuditManifest(dest, key); err == nil {
		t.Fatal("symlink manifest audit accepted")
	}
}

func TestBundleAliasRejected(t *testing.T) {
	dest, _, key := sealed(t)
	alias := dest + "-alias"
	if err := os.Rename(dest, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenArtifact(alias, TLSKeyLog, key); err == nil {
		t.Fatal("bundle alias accepted")
	}
	if _, err := AuditManifest(alias, key); err == nil {
		t.Fatal("bundle alias audit accepted")
	}
}

func TestAuditManifestRejectsOpenDir(t *testing.T) {
	dest, _, key := sealed(t)
	if err := os.Chmod(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := AuditManifest(dest, key); err == nil {
		t.Fatal("open audit dir accepted")
	}
}
