package grumpkin

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	grumpkinecdsa "github.com/consensys/gnark-crypto/ecc/grumpkin/ecdsa"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// PrivKeySize is the full serialized size: compressed pubkey (32) || scalar (32).
const PrivKeySize = 64

// Ensure GrumpkinPrivKey implements the right interface.
var _ cryptotypes.LedgerPrivKey = &GrumpkinPrivKey{}

// GrumpkinPrivKey wraps a gnark-crypto Grumpkin ECDSA private key.
// The key is stored as compressed pubkey (32 bytes) || scalar (32 bytes).
type GrumpkinPrivKey struct {
	Key []byte `json:"key"` // 64 bytes: compressed pubkey (32) || scalar (32)
}

// NewGrumpkinPrivKey creates a [GrumpkinPrivKey] from the given bytes.
// Returns an error if key is not exactly [PrivKeySize] bytes.
func NewGrumpkinPrivKey(key []byte) (*GrumpkinPrivKey, error) {
	if len(key) != PrivKeySize {
		return nil, fmt.Errorf("grumpkin privkey must be %d bytes, got %d", PrivKeySize, len(key))
	}
	return &GrumpkinPrivKey{Key: key}, nil
}

// MustNewGrumpkinPrivKey is like [NewGrumpkinPrivKey] but panics on error.
// Use only with trusted, pre-validated input.
func MustNewGrumpkinPrivKey(key []byte) *GrumpkinPrivKey {
	sk, err := NewGrumpkinPrivKey(key)
	if err != nil {
		panic(err)
	}
	return sk
}

// GenerateKey generates a new random Grumpkin private key.
func GenerateKey() (*GrumpkinPrivKey, error) {
	privKey, err := grumpkinecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	bz := privKey.Bytes()
	key := make([]byte, PrivKeySize)
	copy(key, bz[:PrivKeySize])
	return &GrumpkinPrivKey{Key: key}, nil
}

// Bytes returns a copy of the raw private key bytes.
func (sk *GrumpkinPrivKey) Bytes() []byte {
	cp := make([]byte, len(sk.Key))
	copy(cp, sk.Key)
	return cp
}

// Sign signs the given message using Grumpkin ECDSA.
func (sk *GrumpkinPrivKey) Sign(msg []byte) ([]byte, error) {
	var privKey grumpkinecdsa.PrivateKey
	if _, err := privKey.SetBytes(sk.Key); err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}
	return privKey.Sign(msg, nil)
}

// PubKey derives the corresponding [GrumpkinPubKey] from this private key.
// Returns nil if the stored key material is corrupted and cannot be
// deserialized. Use [PubKeyE] for an error-returning alternative.
func (sk *GrumpkinPrivKey) PubKey() cryptotypes.PubKey {
	pk, err := sk.PubKeyE()
	if err != nil {
		return nil
	}
	return pk
}

// PubKeyE derives the corresponding [GrumpkinPubKey], returning an error if the
// stored key material is corrupted.
func (sk *GrumpkinPrivKey) PubKeyE() (*GrumpkinPubKey, error) {
	var privKey grumpkinecdsa.PrivateKey
	if _, err := privKey.SetBytes(sk.Key); err != nil {
		return nil, fmt.Errorf("failed to deserialize grumpkin private key: %w", err)
	}
	pubBytes := rawXYFromPoint(&privKey.PublicKey.A)
	return &GrumpkinPubKey{Key: pubBytes}, nil
}

// Equals reports whether sk and other represent the same private key.
// Comparison is done in constant time.
func (sk *GrumpkinPrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	otherGrumpkin, ok := other.(*GrumpkinPrivKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(sk.Key, otherGrumpkin.Key) == 1
}

// Type returns the key type identifier.
func (sk *GrumpkinPrivKey) Type() string { return KeyType }

// String returns a redacted representation to avoid leaking key material.
func (sk *GrumpkinPrivKey) String() string { return "GrumpkinPrivKey{...}" }

// ProtoMessage is a no-op required by the proto.Message interface.
func (sk *GrumpkinPrivKey) ProtoMessage() {}

// Reset zeros out the private key material.
func (sk *GrumpkinPrivKey) Reset() {
	for i := range sk.Key {
		sk.Key[i] = 0
	}
}
