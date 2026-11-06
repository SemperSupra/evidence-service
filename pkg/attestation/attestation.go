// Package attestation provides independent Ed25519 signatures over canonical
// evidence manifests. It does not manage private signing keys or TLS secrets.
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const Domain = "SemperSupra/EvidenceService/ManifestAttestation/v1\x00"

// Receipt identifies a signed manifest by digest and signer identity.
// The signer ID is informational; callers must independently trust the public key.
type Receipt struct {
	Version        int    `json:"version"`
	SignerID       string `json:"signer_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Signature      []byte `json:"signature"`
}

func digest(manifest []byte, signerID string) [32]byte {
	h := sha256.New()
	h.Write([]byte(Domain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(signerID)))
	h.Write(length[:])
	h.Write([]byte(signerID))
	h.Write(manifest)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Sign signs the exact supplied manifest bytes. Callers must first canonicalize
// their manifest and must keep the trusted public-key registry out of the receipt.
func Sign(manifest []byte, signerID string, key ed25519.PrivateKey) (Receipt, error) {
	if len(manifest) == 0 || signerID == "" || len(key) != ed25519.PrivateKeySize {
		return Receipt{}, errors.New("invalid attestation input")
	}
	h := digest(manifest, signerID)
	manifestHash := sha256.Sum256(manifest)
	return Receipt{Version: 1, SignerID: signerID, ManifestSHA256: hex.EncodeToString(manifestHash[:]), Signature: ed25519.Sign(key, h[:])}, nil
}

// Verify requires an out-of-band trusted public key. It never accepts a public
// key supplied by an untrusted receipt as its source of signing authority.
func Verify(manifest []byte, receipt Receipt, key ed25519.PublicKey) error {
	if len(manifest) == 0 || receipt.Version != 1 || receipt.SignerID == "" || len(key) != ed25519.PublicKeySize || len(receipt.Signature) != ed25519.SignatureSize {
		return errors.New("invalid attestation")
	}
	h := digest(manifest, receipt.SignerID)
	if receipt.ManifestSHA256 != hex.EncodeToString(sha256Digest(manifest)) || !ed25519.Verify(key, h[:], receipt.Signature) {
		return errors.New("manifest attestation verification failed")
	}
	return nil
}

func sha256Digest(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
