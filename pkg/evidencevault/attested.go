package evidencevault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/SemperSupra/evidence-service/pkg/attestation"
)

// SealAttested publishes a bundle only after all test artifacts and an
// independent signed manifest receipt have been written to a private staging
// directory. The signing key is caller-owned and is never serialized.
func SealAttested(parent, sessionID string, artifacts map[Kind][]byte, masterKEK []byte, signerID string, signingKey ed25519.PrivateKey) (string, Manifest, attestation.Receipt, error) {
	var empty Manifest
	var emptyReceipt attestation.Receipt
	if signerID == "" || len(signingKey) != ed25519.PrivateKeySize {
		return "", empty, emptyReceipt, errors.New("independent signer required")
	}
	if err := secureParent(parent); err != nil {
		return "", empty, emptyReceipt, err
	}
	staging, err := os.MkdirTemp(parent, ".attestation-stage-")
	if err != nil {
		return "", empty, emptyReceipt, err
	}
	defer os.RemoveAll(staging)
	bundle, manifest, err := Seal(staging, sessionID, artifacts, masterKEK)
	if err != nil {
		return "", empty, emptyReceipt, err
	}
	raw, err := readRestricted(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		return "", empty, emptyReceipt, err
	}
	receipt, err := attestation.Sign(raw, signerID, signingKey)
	if err != nil {
		return "", empty, emptyReceipt, err
	}
	doc, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", empty, emptyReceipt, err
	}
	if err := writeRestricted(filepath.Join(bundle, "attestation.json"), append(doc, '\n')); err != nil {
		return "", empty, emptyReceipt, err
	}
	// Best effort durability for the signed stage; real immutable object-store
	// and crash recovery are separate qualification gates.
	if d, err := os.Open(bundle); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	dest := filepath.Join(parent, filepath.Base(bundle))
	if _, err := os.Lstat(dest); err == nil {
		return "", empty, emptyReceipt, errors.New("destination bundle already exists")
	} else if !os.IsNotExist(err) {
		return "", empty, emptyReceipt, err
	}
	if err := os.Rename(bundle, dest); err != nil {
		return "", empty, emptyReceipt, err
	}
	if d, err := os.Open(parent); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return dest, manifest, receipt, nil
}

// OpenAttested authenticates the signed manifest against an independently
// trusted public key before permitting the existing authenticated DEK open.
// The expected signer must be supplied by trusted policy, not the receipt.
func OpenAttested(bundle string, kind Kind, masterKEK []byte, expectedSigner string, trustedKey ed25519.PublicKey) ([]byte, error) {
	if expectedSigner == "" || len(trustedKey) != ed25519.PublicKeySize {
		return nil, errors.New("trusted signer identity and key required")
	}
	if err := secureParent(bundle); err != nil {
		return nil, err
	}
	manifestBefore, err := readRestricted(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		return nil, err
	}
	receiptBefore, err := readRestricted(filepath.Join(bundle, "attestation.json"))
	if err != nil {
		return nil, err
	}
	if len(receiptBefore) > 8192 || len(manifestBefore) > 1<<20 {
		return nil, errors.New("oversized evidence attestation")
	}
	var receipt attestation.Receipt
	if err := json.Unmarshal(receiptBefore, &receipt); err != nil {
		return nil, errors.New("malformed evidence attestation")
	}
	if receipt.SignerID != expectedSigner {
		return nil, errors.New("untrusted evidence signer")
	}
	if err := attestation.Verify(manifestBefore, receipt, trustedKey); err != nil {
		return nil, err
	}
	plain, err := OpenArtifact(bundle, kind, masterKEK)
	if err != nil {
		return nil, err
	}
	// Fail closed if the signed documents changed during the DEK read. This
	// does not replace hostile-filesystem openat/immutable-store qualification.
	manifestAfter, err := readRestricted(filepath.Join(bundle, "manifest.json"))
	if err != nil || !bytes.Equal(manifestBefore, manifestAfter) {
		return nil, errors.New("manifest changed during evidence recovery")
	}
	receiptAfter, err := readRestricted(filepath.Join(bundle, "attestation.json"))
	if err != nil || !bytes.Equal(receiptBefore, receiptAfter) {
		return nil, errors.New("attestation changed during evidence recovery")
	}
	return plain, nil
}
