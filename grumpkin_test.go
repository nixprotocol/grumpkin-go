package grumpkin

import (
	"testing"
)

func TestGenerateKey(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(sk.Key) != PrivKeySize {
		t.Fatalf("expected %d bytes, got %d", PrivKeySize, len(sk.Key))
	}
}

func TestSetBytesRoundTrip(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Bytes() -> NewGrumpkinPrivKey() round-trip
	bz := sk.Bytes()
	sk2 := NewGrumpkinPrivKey(bz)
	if !sk.Equals(sk2) {
		t.Fatal("private key round-trip failed: keys not equal")
	}

	// PubKey round-trip
	pk := sk.PubKey()
	pk2 := sk2.PubKey()
	if !pk.Equals(pk2) {
		t.Fatal("pubkey derived from round-tripped privkey differs")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("hello nixchain")
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pk := sk.PubKey()
	if !pk.VerifySignature(msg, sig) {
		t.Fatal("signature verification failed")
	}

	// Verify with wrong message fails
	if pk.VerifySignature([]byte("wrong message"), sig) {
		t.Fatal("signature should not verify with wrong message")
	}
}

func TestPubKeyAddress(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pk := sk.PubKey()
	addr := pk.Address()
	if addr == nil {
		t.Fatal("Address() returned nil")
	}
	if len(addr) != 20 {
		t.Fatalf("expected 20-byte address, got %d", len(addr))
	}
}

func TestPrivKeyReset(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sk.Reset()
	for i, b := range sk.Key {
		if b != 0 {
			t.Fatalf("Reset did not zero byte %d: got %d", i, b)
		}
	}
}

func TestBytesReturnsCopy(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// PrivKey.Bytes() should return a copy
	bz := sk.Bytes()
	bz[0] ^= 0xff
	if bz[0] == sk.Key[0] {
		t.Fatal("PrivKey.Bytes() returned a mutable reference")
	}

	// PubKey.Bytes() should return a copy
	pk := sk.PubKey().(*GrumpkinPubKey)
	pbz := pk.Bytes()
	pbz[0] ^= 0xff
	if pbz[0] == pk.Key[0] {
		t.Fatal("PubKey.Bytes() returned a mutable reference")
	}
}

func TestNewGrumpkinPubKeyFromBytes(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pk := sk.PubKey().(*GrumpkinPubKey)

	// Valid bytes should succeed
	pk2, err := NewGrumpkinPubKeyFromBytes(pk.Key)
	if err != nil {
		t.Fatalf("NewGrumpkinPubKeyFromBytes: %v", err)
	}
	if !pk.Equals(pk2) {
		t.Fatal("pubkeys should be equal")
	}

	// Wrong length should error
	_, err = NewGrumpkinPubKeyFromBytes([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for wrong length")
	}

	// Invalid point should error
	badKey := make([]byte, PubKeySize)
	badKey[0] = 0xff
	_, err = NewGrumpkinPubKeyFromBytes(badKey)
	if err == nil {
		t.Fatal("expected error for invalid curve point")
	}
}

func TestNewGrumpkinPrivKeyFromBytes(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Valid bytes should succeed
	sk2, err := NewGrumpkinPrivKeyFromBytes(sk.Key)
	if err != nil {
		t.Fatalf("NewGrumpkinPrivKeyFromBytes: %v", err)
	}
	if !sk.Equals(sk2) {
		t.Fatal("privkeys should be equal")
	}

	// Wrong length should error
	_, err = NewGrumpkinPrivKeyFromBytes([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}
