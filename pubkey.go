// Package grumpkin provides Grumpkin elliptic-curve key types for Cosmos SDK
// chains. The Grumpkin curve is the cycle-companion of BN254 and is widely used
// in zero-knowledge proof systems (Noir / Barretenberg, Halo2, etc.).
//
// This package implements [cryptotypes.PubKey] and [cryptotypes.LedgerPrivKey]
// so that Grumpkin keys can be used directly with the Cosmos SDK keyring,
// codec, and transaction signing pipeline.
//
// Addresses are derived via Poseidon2(pk.X, pk.Y) truncated to 20 bytes,
// giving ZK-friendly address derivation instead of SHA-256/RIPEMD-160.
package grumpkin

import (
	"crypto/subtle"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	grumpkinecdsa "github.com/consensys/gnark-crypto/ecc/grumpkin/ecdsa"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	poseidon2 "github.com/nixprotocol/poseidon2-go"
)

const (
	// PubKeyName is the Amino type name for Grumpkin public keys.
	PubKeyName = "nix/GrumpkinPubKey"
	// PubKeySize is the uncompressed public key size: 32 bytes X + 32 bytes Y.
	PubKeySize = 64
	// KeyType is the key type identifier used throughout the Cosmos SDK.
	KeyType = "grumpkin"
)

var _ cryptotypes.PubKey = &GrumpkinPubKey{}

// GrumpkinPubKey wraps a Grumpkin elliptic-curve public key stored as raw
// X (32 bytes) || Y (32 bytes) in uncompressed form.
type GrumpkinPubKey struct {
	Key []byte `json:"key"` // 64 bytes: X (32) || Y (32)
}

// NewGrumpkinPubKey creates a [GrumpkinPubKey] from the given bytes after
// validating both the length and that the bytes represent a valid point on the
// Grumpkin curve. Returns an error if the input is invalid.
func NewGrumpkinPubKey(key []byte) (*GrumpkinPubKey, error) {
	if len(key) != PubKeySize {
		return nil, fmt.Errorf("grumpkin pubkey must be %d bytes, got %d", PubKeySize, len(key))
	}
	if _, err := pointFromRawXY(key); err != nil {
		return nil, fmt.Errorf("grumpkin pubkey bytes are not a valid curve point: %w", err)
	}
	return &GrumpkinPubKey{Key: key}, nil
}

// MustNewGrumpkinPubKey is like [NewGrumpkinPubKey] but panics on error.
// Use only with trusted, pre-validated input (e.g. from your own keygen).
func MustNewGrumpkinPubKey(key []byte) *GrumpkinPubKey {
	pk, err := NewGrumpkinPubKey(key)
	if err != nil {
		panic(err)
	}
	return pk
}

// pointFromRawXY reconstructs a G1Affine point from raw X||Y bytes (no metadata
// bits) and validates it lies on the curve.
func pointFromRawXY(key []byte) (*grumpkin.G1Affine, error) {
	var p grumpkin.G1Affine
	p.X.SetBytes(key[:32])
	p.Y.SetBytes(key[32:])
	if !p.IsOnCurve() {
		return nil, fmt.Errorf("point is not on the Grumpkin curve")
	}
	return &p, nil
}

// rawXYFromPoint serializes a G1Affine point to raw X (32) || Y (32) without
// metadata bits.
func rawXYFromPoint(p *grumpkin.G1Affine) []byte {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	out := make([]byte, PubKeySize)
	copy(out[:32], xBytes[:])
	copy(out[32:], yBytes[:])
	return out
}

// Address returns the Cosmos SDK address derived as Poseidon2(pk.X, pk.Y)
// truncated to 20 bytes. This gives a ZK-friendly address derivation path.
// Returns nil if the key has invalid length.
func (pk *GrumpkinPubKey) Address() cryptotypes.Address {
	if len(pk.Key) != PubKeySize {
		return nil
	}

	var x, y fr.Element
	x.SetBytes(pk.Key[:32])
	y.SetBytes(pk.Key[32:])

	hash := poseidon2.Hash2(x, y)
	hashBytes := hash.Bytes()
	return cryptotypes.Address(hashBytes[12:32])
}

// Bytes returns a copy of the raw public key bytes.
func (pk *GrumpkinPubKey) Bytes() []byte {
	cp := make([]byte, len(pk.Key))
	copy(cp, pk.Key)
	return cp
}

// VerifySignature verifies a Grumpkin ECDSA signature over the given message.
// Returns false for any malformed key or signature.
func (pk *GrumpkinPubKey) VerifySignature(msg []byte, sig []byte) bool {
	if len(pk.Key) != PubKeySize {
		return false
	}
	p, err := pointFromRawXY(pk.Key)
	if err != nil {
		return false
	}
	var pubKey grumpkinecdsa.PublicKey
	pubKey.A.Set(p)
	ok, err := pubKey.Verify(sig, msg, nil)
	if err != nil {
		return false
	}
	return ok
}

// Equals reports whether pk and other represent the same public key.
// Comparison is done in constant time.
func (pk *GrumpkinPubKey) Equals(other cryptotypes.PubKey) bool {
	otherGrumpkin, ok := other.(*GrumpkinPubKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pk.Key, otherGrumpkin.Key) == 1
}

// Type returns the key type identifier.
func (pk *GrumpkinPubKey) Type() string { return KeyType }

// String returns a human-readable hex representation.
func (pk *GrumpkinPubKey) String() string { return fmt.Sprintf("GrumpkinPubKey{%X}", pk.Key) }

// Reset is a no-op; public keys do not contain secret material.
func (pk *GrumpkinPubKey) Reset() {}

// ProtoMessage is a no-op required by the proto.Message interface.
func (pk *GrumpkinPubKey) ProtoMessage() {}
