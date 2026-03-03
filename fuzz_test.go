package grumpkin

import (
	"testing"
)

// FuzzNewGrumpkinPubKey tests that arbitrary bytes never cause a panic in the
// error-returning constructor and that any successfully created key produces
// a valid 20-byte address.
func FuzzNewGrumpkinPubKey(f *testing.F) {
	// Seed with a valid key
	sk, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	pkE, _ := sk.PubKeyE()
	f.Add(pkE.Key)

	// Seed with edge cases
	f.Add(make([]byte, 0))
	f.Add(make([]byte, PubKeySize))
	f.Add(make([]byte, PubKeySize+1))

	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := NewGrumpkinPubKey(data)
		if err != nil {
			return // expected for most random inputs
		}
		// If constructor succeeded, invariants must hold
		if len(pk.Key) != PubKeySize {
			t.Fatalf("key length = %d, want %d", len(pk.Key), PubKeySize)
		}
		addr := pk.Address()
		if addr == nil {
			t.Fatal("Address() returned nil for valid key")
		}
		if len(addr) != 20 {
			t.Fatalf("address length = %d, want 20", len(addr))
		}
	})
}

// FuzzNewGrumpkinPrivKey tests that arbitrary bytes never cause a panic.
func FuzzNewGrumpkinPrivKey(f *testing.F) {
	sk, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	f.Add(sk.Key)
	f.Add(make([]byte, 0))
	f.Add(make([]byte, PrivKeySize))

	f.Fuzz(func(t *testing.T, data []byte) {
		sk, err := NewGrumpkinPrivKey(data)
		if err != nil {
			return
		}
		if len(sk.Key) != PrivKeySize {
			t.Fatalf("key length = %d, want %d", len(sk.Key), PrivKeySize)
		}
	})
}

// FuzzVerifySignature tests that arbitrary message/signature pairs never panic.
func FuzzVerifySignature(f *testing.F) {
	sk, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	pk := sk.PubKey().(*GrumpkinPubKey)

	// Seed with a valid signature
	msg := []byte("hello")
	sig, _ := sk.Sign(msg)
	f.Add(msg, sig)

	// Seed with edge cases
	f.Add([]byte{}, []byte{})
	f.Add([]byte("test"), []byte{0xff})

	f.Fuzz(func(t *testing.T, msg, sig []byte) {
		// Must not panic — result doesn't matter
		pk.VerifySignature(msg, sig)
	})
}

// FuzzAddressDerivation tests that address derivation never panics on valid
// keys created from arbitrary 64-byte inputs that happen to be on the curve.
func FuzzAddressDerivation(f *testing.F) {
	sk, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	pkE, _ := sk.PubKeyE()
	f.Add(pkE.Key)

	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := NewGrumpkinPubKey(data)
		if err != nil {
			return
		}
		addr := pk.Address()
		if addr == nil {
			t.Fatal("valid pubkey produced nil address")
		}
		if len(addr) != 20 {
			t.Fatalf("address length = %d, want 20", len(addr))
		}
	})
}

// FuzzSign tests that Sign never panics on arbitrary messages with a valid key.
func FuzzSign(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add(make([]byte, 256))

	sk, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		sig, err := sk.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !sk.PubKey().VerifySignature(msg, sig) {
			t.Fatal("valid signature did not verify")
		}
	})
}

// FuzzKeyDeserialization tests round-trip for arbitrary inputs that pass
// validation.
func FuzzKeyDeserialization(f *testing.F) {
	sk, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	f.Add(sk.Key)
	f.Add(make([]byte, PrivKeySize))

	f.Fuzz(func(t *testing.T, data []byte) {
		sk, err := NewGrumpkinPrivKey(data)
		if err != nil {
			return
		}
		// If constructor succeeded, PubKey should not panic
		pk := sk.PubKey()
		if pk == nil {
			// corrupted key material — acceptable
			return
		}
		// If PubKey succeeded, verify sign/verify round-trip
		sig, err := sk.Sign([]byte("fuzz"))
		if err != nil {
			return // key material might be invalid for signing
		}
		if !pk.VerifySignature([]byte("fuzz"), sig) {
			t.Fatal("sign/verify round-trip failed for deserialized key")
		}
	})
}
