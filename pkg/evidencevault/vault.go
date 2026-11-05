// Package tlsevidencevault is a synthetic-only evidence retention experiment.
// It does not collect TLS secrets or authorize disclosure of captured traffic.
package evidencevault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const Schema = "browserparity.tls-evidence-bundle.test-v1"
const maxFixtureBytes = 32 << 20

// Artifact types are fixed so untrusted strings cannot become filesystem paths.
type Kind string

const (
	EncryptedCapture  Kind = "encrypted_capture"
	DecryptedEvidence Kind = "decrypted_evidence"
	TLSKeyLog         Kind = "tls_key_log"
)

var kinds = []Kind{EncryptedCapture, DecryptedEvidence, TLSKeyLog}
var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)

// Entry fields describe ciphertext and plaintext identity; they contain no key material.
type Entry struct {
	PlainSHA256   string `json:"plaintext_sha256"`
	SealedSHA256  string `json:"sealed_sha256"`
	WrappedSHA256 string `json:"wrapped_key_sha256"`
	PlainBytes    int    `json:"plaintext_bytes"`
}
type Manifest struct {
	Schema       string         `json:"schema"`
	TestDataOnly bool           `json:"test_data_only"`
	SessionID    string         `json:"session_id"`
	BundleID     string         `json:"bundle_id"`
	Entries      map[Kind]Entry `json:"artifacts"`
	MAC          string         `json:"manifest_hmac_sha256"`
}

func hash(b []byte) string         { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func random(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }
func secureParent(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("bundle parent must be a real directory")
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("bundle parent must deny group/other access")
	}
	return nil
}
func encrypt(key, plain []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := random(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}
func decrypt(key, all []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(all) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("invalid sealed object")
	}
	return aead.Open(nil, all[:aead.NonceSize()], all[aead.NonceSize():], []byte(aad))
}
func aad(m Manifest, kind Kind, role string) string {
	return m.Schema + "|" + m.SessionID + "|" + m.BundleID + "|" + string(kind) + "|" + role
}
func authManifest(m Manifest, master []byte) (string, error) {
	m.MAC = ""
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	// Domain separation for metadata HMAC; the key-encrypting key is external.
	deriv := hmac.New(sha256.New, master)
	deriv.Write([]byte("BrowserParity test manifest auth v1"))
	mac := hmac.New(sha256.New, deriv.Sum(nil))
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
func writeRestricted(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	syncerr := f.Sync()
	closeerr := f.Close()
	if werr != nil {
		return werr
	}
	if syncerr != nil {
		return syncerr
	}
	return closeerr
}

// Seal persists encrypted copies of all three TEST artifacts. masterKEK is supplied
// by a separate vault/TPM/KMS abstraction and is NEVER written into this bundle.
func Seal(parent, sessionID string, artifacts map[Kind][]byte, masterKEK []byte) (string, Manifest, error) {
	var m Manifest
	if len(masterKEK) != 32 {
		return "", m, errors.New("32-byte external wrapping key required")
	}
	if !validID.MatchString(sessionID) {
		return "", m, errors.New("invalid session identifier")
	}
	if err := secureParent(parent); err != nil {
		return "", m, err
	}
	if len(artifacts) != len(kinds) {
		return "", m, errors.New("three evidence artifacts required")
	}
	for _, kind := range kinds {
		b, ok := artifacts[kind]
		if !ok || len(b) == 0 || len(b) > maxFixtureBytes {
			return "", m, fmt.Errorf("missing/empty/oversize test artifact: %s", kind)
		}
	}
	bid, err := random(16)
	if err != nil {
		return "", m, err
	}
	m = Manifest{Schema: Schema, TestDataOnly: true, SessionID: sessionID, BundleID: hex.EncodeToString(bid), Entries: make(map[Kind]Entry)}
	temp, err := os.MkdirTemp(parent, ".sealed-")
	if err != nil {
		return "", m, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(temp)
		}
	}()
	for _, kind := range kinds {
		plain := artifacts[kind]
		dek, err := random(32)
		if err != nil {
			return "", m, err
		}
		blob, err := encrypt(dek, plain, aad(m, kind, "body"))
		if err != nil {
			return "", m, err
		}
		wrapped, err := encrypt(masterKEK, dek, aad(m, kind, "wrap"))
		if err != nil {
			return "", m, err
		}
		for i := range dek {
			dek[i] = 0
		} // best effort, not a secure-memory guarantee
		if err := writeRestricted(filepath.Join(temp, string(kind)+".sealed"), blob); err != nil {
			return "", m, err
		}
		if err := writeRestricted(filepath.Join(temp, string(kind)+".wrapped"), wrapped); err != nil {
			return "", m, err
		}
		m.Entries[kind] = Entry{PlainSHA256: hash(plain), SealedSHA256: hash(blob), WrappedSHA256: hash(wrapped), PlainBytes: len(plain)}
	}
	mac, err := authManifest(m, masterKEK)
	if err != nil {
		return "", m, err
	}
	m.MAC = mac
	doc, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", m, err
	}
	if err := writeRestricted(filepath.Join(temp, "manifest.json"), append(doc, '\n')); err != nil {
		return "", m, err
	}
	dest := filepath.Join(parent, "session-"+m.BundleID)
	if err := os.Rename(temp, dest); err != nil {
		return "", m, err
	}
	if d, err := os.Open(parent); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	success = true
	return dest, m, nil
}

// OpenArtifact is an authorized analysis-worker primitive, NOT a user/agent API.
// A production caller must separately authorize who may open which artifact.
func OpenArtifact(bundle string, kind Kind, masterKEK []byte) ([]byte, error) {
	if len(masterKEK) != 32 {
		return nil, errors.New("32-byte external wrapping key required")
	}
	known := false
	for _, k := range kinds {
		if kind == k {
			known = true
		}
	}
	if !known {
		return nil, errors.New("unknown artifact kind")
	}
	if err := secureParent(bundle); err != nil {
		return nil, err
	}
	raw, err := readRestricted(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Schema != Schema || !m.TestDataOnly || !validID.MatchString(m.SessionID) || len(m.BundleID) != 32 ||
		filepath.Base(bundle) != "session-"+m.BundleID {
		return nil, errors.New("invalid test-only manifest identity")
	}
	expected, err := authManifest(m, masterKEK)
	if err != nil {
		return nil, err
	}
	provided, err := hex.DecodeString(m.MAC)
	if err != nil {
		return nil, errors.New("invalid manifest authentication")
	}
	expectedBytes, _ := hex.DecodeString(expected)
	if !hmac.Equal(provided, expectedBytes) {
		return nil, errors.New("manifest authentication failed")
	}
	entry, ok := m.Entries[kind]
	if !ok {
		return nil, errors.New("missing artifact record")
	}
	// Files are fixed names; reject symlinks before reading. Directory is owner-only.
	load := func(suffix string) ([]byte, error) {
		return readRestricted(filepath.Join(bundle, string(kind)+suffix))
	}
	wrapped, err := load(".wrapped")
	if err != nil {
		return nil, err
	}
	blob, err := load(".sealed")
	if err != nil {
		return nil, err
	}
	if hash(wrapped) != entry.WrappedSHA256 || hash(blob) != entry.SealedSHA256 {
		return nil, errors.New("ciphertext custody hash mismatch")
	}
	dek, err := decrypt(masterKEK, wrapped, aad(m, kind, "wrap"))
	if err != nil {
		return nil, errors.New("wrapped key authentication failed")
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	plain, err := decrypt(dek, blob, aad(m, kind, "body"))
	if err != nil {
		return nil, errors.New("artifact authentication failed")
	}
	if hash(plain) != entry.PlainSHA256 || len(plain) != entry.PlainBytes {
		return nil, errors.New("plaintext identity mismatch")
	}
	return plain, nil
}

// readRestricted refuses non-regular objects, symlinks and loose permissions.
// This function is for local synthetic fixtures, not a full hostile-filesystem
// openat(O_NOFOLLOW) implementation; production deployment requires an isolated
// evidence owner and immutable storage.
func readRestricted(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("insecure evidence artifact")
	}
	return os.ReadFile(path)
}

// AuditManifest exposes only authenticated nonsecret references after an unlock.
func AuditManifest(bundle string, masterKEK []byte) (Manifest, error) {
	var m Manifest
	if len(masterKEK) != 32 {
		return m, errors.New("invalid external key")
	}
	if err := secureParent(bundle); err != nil {
		return m, err
	}
	b, err := readRestricted(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Schema != Schema || !m.TestDataOnly || !validID.MatchString(m.SessionID) ||
		len(m.BundleID) != 32 || filepath.Base(bundle) != "session-"+m.BundleID || len(m.Entries) != len(kinds) {
		return Manifest{}, errors.New("invalid evidence manifest identity")
	}
	expected, err := authManifest(m, masterKEK)
	if err != nil {
		return m, err
	}
	e, _ := hex.DecodeString(expected)
	provided, err := hex.DecodeString(m.MAC)
	if err != nil || !hmac.Equal(e, provided) {
		return Manifest{}, errors.New("manifest authentication failed")
	}
	return m, nil
}
