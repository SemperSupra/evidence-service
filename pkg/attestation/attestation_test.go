package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestAttestationRoundTripAndNegatives(t *testing.T) {
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	other, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := []byte(`{"capture":"synthetic","stream":7}`)
	r, e := Sign(m, "test-signer", k)
	if e != nil {
		t.Fatal(e)
	}
	if e = Verify(m, r, p); e != nil {
		t.Fatal(e)
	}
	for name, tc := range map[string]struct {
		m []byte
		r Receipt
		p ed25519.PublicKey
	}{
		"altered":   {m: append(bytes.Clone(m), ' '), r: r, p: p},
		"wrong-key": {m: m, r: r, p: other},
		"version":   {m: m, r: func() Receipt { x := r; x.Version = 2; return x }(), p: p},
		"signer-id": {m: m, r: func() Receipt { x := r; x.SignerID = "attacker"; return x }(), p: p},
		"signature": {m: m, r: func() Receipt { x := r; x.Signature = bytes.Clone(r.Signature); x.Signature[0] ^= 1; return x }(), p: p},
	} {
		t.Run(name, func(t *testing.T) {
			if Verify(tc.m, tc.r, tc.p) == nil {
				t.Fatal("accepted invalid attestation")
			}
		})
	}
}
func TestInvalidInput(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := Sign(nil, "x", k); e == nil {
		t.Fatal("empty manifest accepted")
	}
	if _, e := Sign([]byte("x"), "", k); e == nil {
		t.Fatal("empty signer accepted")
	}
	if _, e := Sign([]byte("x"), "test", nil); e == nil {
		t.Fatal("invalid key accepted")
	}
}
