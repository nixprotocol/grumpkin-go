package grumpkin

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// GrumpkinAlgoName is the algorithm name registered with the Cosmos SDK keyring.
const GrumpkinAlgoName = "grumpkin"

// GrumpkinAlgo is a [keyring.SignatureAlgo] that produces Grumpkin keys from
// BIP-39 mnemonics. It derives a seed using the standard secp256k1 HD path
// and then reduces the 32-byte result modulo the Grumpkin scalar field order.
var GrumpkinAlgo = grumpkinAlgo{}

var _ keyring.SignatureAlgo = grumpkinAlgo{}

type grumpkinAlgo struct{}

// Name returns the algorithm name.
func (grumpkinAlgo) Name() hd.PubKeyType {
	return hd.PubKeyType(GrumpkinAlgoName)
}

// Derive returns a derivation function that produces a 64-byte Grumpkin private
// key from a BIP-39 mnemonic and HD path.
func (grumpkinAlgo) Derive() hd.DeriveFn {
	return func(mnemonic string, bip39Passphrase, hdPath string) ([]byte, error) {
		deriveFn := hd.Secp256k1.Derive()
		bz, err := deriveFn(mnemonic, bip39Passphrase, hdPath)
		if err != nil {
			return nil, err
		}

		// Reduce the 32-byte seed modulo the Grumpkin scalar field order
		// (which equals the BN254 base field modulus) to get a valid scalar.
		var scalar fr.Element
		scalar.SetBytes(bz[:32])

		if scalar.IsZero() {
			return nil, fmt.Errorf("derived grumpkin scalar is zero")
		}

		fullKey, err := privKeyFromScalar(scalar)
		if err != nil {
			return nil, fmt.Errorf("failed to build grumpkin key from derived scalar: %w", err)
		}

		return fullKey, nil
	}
}

// privKeyFromScalar constructs a full 64-byte Grumpkin private key
// (compressed pubkey || scalar) from a field element scalar.
func privKeyFromScalar(scalar fr.Element) ([]byte, error) {
	scalarBytes := scalar.Bytes()
	scalarInt := new(big.Int).SetBytes(scalarBytes[:])

	var pubPoint grumpkin.G1Affine
	pubPoint.ScalarMultiplicationBase(scalarInt)

	pubBytes := pubPoint.Bytes()
	fullKey := make([]byte, PrivKeySize)
	copy(fullKey[:32], pubBytes[:])
	copy(fullKey[32:], scalarBytes[:])

	return fullKey, nil
}

// Generate returns a key generation function that wraps raw bytes into a
// [GrumpkinPrivKey].
func (grumpkinAlgo) Generate() hd.GenerateFn {
	return func(bz []byte) cryptotypes.PrivKey {
		if len(bz) != PrivKeySize {
			panic(fmt.Sprintf("invalid seed length for grumpkin key generation: expected %d, got %d", PrivKeySize, len(bz)))
		}
		key := make([]byte, PrivKeySize)
		copy(key, bz)
		return &GrumpkinPrivKey{Key: key}
	}
}
