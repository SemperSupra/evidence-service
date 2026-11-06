// Package kmsbundle binds an independently attested synthetic evidence bundle
// to a Transit-wrapped random bundle key. This is not a production vault or an
// authorization interface; only an already-approved worker may call Open.
package kmsbundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SemperSupra/evidence-service/pkg/evidencevault"
)

const Schema = "evidence-service.kms-bundle.test-v1"
const domain = "SemperSupra/EvidenceService/KMSBundle/v1\x00"
const maxEnvelopeBytes = 16 << 10
const maxManifestBytes = 1 << 20

// Wrapper is satisfied by the existing transitclient.Client. The worker must
// independently authenticate to a derived, restricted Transit key. No raw
// session secret is exported by this interface.
type Wrapper interface {
	WrapKey(context.Context, []byte, []byte) (string, error)
	UnwrapKey(context.Context, string, []byte) ([]byte, error)
}

// Binding is the signed, non-secret reference from a specific evidence
// manifest to its KMS-protected bundle key.
type Binding struct {
	Schema         string `json:"schema"`
	SessionID      string `json:"session_id"`
	BundleID       string `json:"bundle_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TransitScope   string `json:"transit_scope"`
	WrappedKey     string `json:"wrapped_key"`
	SignerID       string `json:"signer_id"`
}

type Receipt struct {
	Binding   Binding `json:"binding"`
	Signature []byte  `json:"signature"`
}

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func signedDigest(binding Binding) ([32]byte, error) {
	raw, err := json.Marshal(binding)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(raw)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func scope(m evidencevault.Manifest) []byte {
	return []byte("evidence-service-kmsbundle/v1/" + m.SessionID + "/" + m.BundleID)
}

func privateDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return errors.New("insecure evidence directory")
	}
	return nil
}

func readPrivate(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() <= 0 || st.Size() > limit {
		return nil, errors.New("unsafe or oversized evidence record")
	}
	return os.ReadFile(path)
}

func writePrivate(path string, content []byte) error {
	if len(content) == 0 || len(content) > maxEnvelopeBytes {
		return errors.New("invalid evidence envelope size")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(content)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// Seal publishes to parent only after an independently signed manifest,
// separately signed KMS binding and restricted ciphertexts exist in staging.
// The 32-byte random bundle KEK is never serialized in the evidence store.
func Seal(ctx context.Context, parent, sessionID string, artifacts map[evidencevault.Kind][]byte, wrapper Wrapper, signerID string, signer ed25519.PrivateKey) (string, error) {
	if wrapper == nil || signerID == "" || len(signer) != ed25519.PrivateKeySize {
		return "", errors.New("trusted KMS and independent signer required")
	}
	if err := privateDirectory(parent); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(parent, ".kms-stage-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return "", err
	}
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	bundle, m, _, err := evidencevault.SealAttested(stage, sessionID, artifacts, kek, signerID, signer)
	if err != nil {
		return "", err
	}
	manifest, err := readPrivate(filepath.Join(bundle, "manifest.json"), maxManifestBytes)
	if err != nil {
		return "", err
	}
	wrapped, err := wrapper.WrapKey(ctx, kek, scope(m))
	if err != nil {
		return "", errors.New("KMS key wrapping failed")
	}
	if len(wrapped) > 8192 || !strings.HasPrefix(wrapped, "vault:v") {
		return "", errors.New("invalid KMS wrapped-key reference")
	}
	binding := Binding{
		Schema: Schema, SessionID: m.SessionID, BundleID: m.BundleID,
		ManifestSHA256: hash(manifest), TransitScope: string(scope(m)),
		WrappedKey: wrapped, SignerID: signerID,
	}
	digest, err := signedDigest(binding)
	if err != nil {
		return "", err
	}
	record, err := json.MarshalIndent(Receipt{Binding: binding, Signature: ed25519.Sign(signer, digest[:])}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writePrivate(filepath.Join(bundle, "kms-envelope.json"), append(record, '\n')); err != nil {
		return "", err
	}
	if d, err := os.Open(bundle); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	dest := filepath.Join(parent, filepath.Base(bundle))
	if _, err := os.Lstat(dest); err == nil {
		return "", errors.New("evidence destination collision")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(bundle, dest); err != nil {
		return "", err
	}
	if d, err := os.Open(parent); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return dest, nil
}

// Open verifies both signatures, scope and manifest identity BEFORE invoking
// KMS unwrap, then invokes the pre-existing attested artifact reader. Callers
// must independently authorize the actor, session and artifact operation.
func Open(ctx context.Context, bundle string, kind evidencevault.Kind, wrapper Wrapper, expectedSigner string, trustedKey ed25519.PublicKey) ([]byte, error) {
	if wrapper == nil || expectedSigner == "" || len(trustedKey) != ed25519.PublicKeySize {
		return nil, errors.New("trusted KMS and signing identity required")
	}
	if err := privateDirectory(bundle); err != nil {
		return nil, err
	}
	raw, err := readPrivate(filepath.Join(bundle, "kms-envelope.json"), maxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	var record Receipt
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return nil, errors.New("invalid KMS evidence record")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing KMS evidence record")
	}
	b := record.Binding
	if b.Schema != Schema || b.SignerID != expectedSigner || len(record.Signature) != ed25519.SignatureSize {
		return nil, errors.New("untrusted KMS binding")
	}
	digest, err := signedDigest(b)
	if err != nil || !ed25519.Verify(trustedKey, digest[:], record.Signature) {
		return nil, errors.New("KMS envelope signature invalid")
	}
	manifestRaw, err := readPrivate(filepath.Join(bundle, "manifest.json"), maxManifestBytes)
	if err != nil {
		return nil, err
	}
	var m evidencevault.Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, errors.New("invalid evidence manifest")
	}
	if m.Schema != evidencevault.Schema || !m.TestDataOnly ||
		m.SessionID != b.SessionID || m.BundleID != b.BundleID ||
		filepath.Base(bundle) != "session-"+m.BundleID ||
		b.ManifestSHA256 != hash(manifestRaw) || b.TransitScope != string(scope(m)) {
		return nil, errors.New("KMS envelope and evidence manifest mismatch")
	}
	if len(b.WrappedKey) > 8192 || !strings.HasPrefix(b.WrappedKey, "vault:v") {
		return nil, errors.New("invalid wrapped key")
	}
	kek, err := wrapper.UnwrapKey(ctx, b.WrappedKey, scope(m))
	if err != nil || len(kek) != 32 {
		return nil, errors.New("KMS key recovery rejected")
	}
	defer func() {
		for i := range kek {
			kek[i] = 0
		}
	}()
	return evidencevault.OpenAttested(bundle, kind, kek, expectedSigner, trustedKey)
}
