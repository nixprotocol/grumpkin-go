package grumpkin

import (
	"bytes"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// ---------------------------------------------------------------------------
// Key Generation
// ---------------------------------------------------------------------------

func TestGenerateKey(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(sk.Key) != PrivKeySize {
		t.Fatalf("expected %d bytes, got %d", PrivKeySize, len(sk.Key))
	}
}

func TestGenerateKeyUniqueness(t *testing.T) {
	sk1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 1: %v", err)
	}
	sk2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}
	if sk1.Equals(sk2) {
		t.Fatal("two generated keys should not be equal")
	}
}

// ---------------------------------------------------------------------------
// Constructors — error-returning
// ---------------------------------------------------------------------------

func TestNewGrumpkinPubKey(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkE, err := sk.PubKeyE()
	if err != nil {
		t.Fatalf("PubKeyE: %v", err)
	}

	// Valid bytes
	pk2, err := NewGrumpkinPubKey(pkE.Key)
	if err != nil {
		t.Fatalf("NewGrumpkinPubKey: %v", err)
	}
	if !pkE.Equals(pk2) {
		t.Fatal("pubkeys should be equal")
	}

	// Wrong length
	_, err = NewGrumpkinPubKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for wrong length")
	}

	// Empty
	_, err = NewGrumpkinPubKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}

	// Correct length but not on curve
	badKey := make([]byte, PubKeySize)
	badKey[0] = 0xff
	_, err = NewGrumpkinPubKey(badKey)
	if err == nil {
		t.Fatal("expected error for invalid curve point")
	}

	// All zeros — (0,0) is the identity point and passes IsOnCurve in gnark.
	// Verify the constructor accepts it (it is technically on the curve).
	zeroKey := make([]byte, PubKeySize)
	_, err = NewGrumpkinPubKey(zeroKey)
	if err != nil {
		t.Fatalf("zero point (identity) should be accepted: %v", err)
	}
}

func TestNewGrumpkinPrivKey(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Valid bytes
	sk2, err := NewGrumpkinPrivKey(sk.Key)
	if err != nil {
		t.Fatalf("NewGrumpkinPrivKey: %v", err)
	}
	if !sk.Equals(sk2) {
		t.Fatal("privkeys should be equal")
	}

	// Wrong length
	_, err = NewGrumpkinPrivKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for wrong length")
	}

	// Empty
	_, err = NewGrumpkinPrivKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}

	// Too long
	_, err = NewGrumpkinPrivKey(make([]byte, 128))
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

// ---------------------------------------------------------------------------
// Constructors — Must (panic) variants
// ---------------------------------------------------------------------------

func TestMustNewGrumpkinPubKey(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkE, _ := sk.PubKeyE()

	// Valid — should not panic
	pk := MustNewGrumpkinPubKey(pkE.Key)
	if !pkE.Equals(pk) {
		t.Fatal("pubkeys should be equal")
	}

	// Invalid — should panic
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid input")
		}
	}()
	MustNewGrumpkinPubKey([]byte{1, 2, 3})
}

func TestMustNewGrumpkinPrivKey(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Valid
	sk2 := MustNewGrumpkinPrivKey(sk.Key)
	if !sk.Equals(sk2) {
		t.Fatal("privkeys should be equal")
	}

	// Invalid — should panic
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid input")
		}
	}()
	MustNewGrumpkinPrivKey([]byte{1, 2, 3})
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

func TestSetBytesRoundTrip(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	bz := sk.Bytes()
	sk2, err := NewGrumpkinPrivKey(bz)
	if err != nil {
		t.Fatalf("NewGrumpkinPrivKey: %v", err)
	}
	if !sk.Equals(sk2) {
		t.Fatal("private key round-trip failed: keys not equal")
	}

	pk := sk.PubKey()
	pk2 := sk2.PubKey()
	if !pk.Equals(pk2) {
		t.Fatal("pubkey derived from round-tripped privkey differs")
	}
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

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

	if pk.VerifySignature([]byte("wrong message"), sig) {
		t.Fatal("signature should not verify with wrong message")
	}
}

func TestSignEmptyMessage(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sig, err := sk.Sign([]byte{})
	if err != nil {
		t.Fatalf("Sign empty: %v", err)
	}
	pk := sk.PubKey()
	if !pk.VerifySignature([]byte{}, sig) {
		t.Fatal("empty message signature should verify")
	}
}

func TestSignNilMessage(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sig, err := sk.Sign(nil)
	if err != nil {
		t.Fatalf("Sign nil: %v", err)
	}
	pk := sk.PubKey()
	if !pk.VerifySignature(nil, sig) {
		t.Fatal("nil message signature should verify")
	}
}

func TestSignLargeMessage(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := make([]byte, 1<<16) // 64 KiB
	for i := range msg {
		msg[i] = byte(i)
	}
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign large: %v", err)
	}
	if !sk.PubKey().VerifySignature(msg, sig) {
		t.Fatal("large message signature should verify")
	}
}

func TestVerifySignature_MalformedInputs(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pk := sk.PubKey().(*GrumpkinPubKey)
	msg := []byte("test")
	sig, _ := sk.Sign(msg)

	// Wrong key length
	badPK := &GrumpkinPubKey{Key: []byte{1, 2, 3}}
	if badPK.VerifySignature(msg, sig) {
		t.Fatal("should fail with wrong key length")
	}

	// Invalid curve point in key
	invalidPK := &GrumpkinPubKey{Key: make([]byte, PubKeySize)}
	invalidPK.Key[0] = 0xff
	if invalidPK.VerifySignature(msg, sig) {
		t.Fatal("should fail with invalid curve point")
	}

	// Truncated signature
	if pk.VerifySignature(msg, sig[:len(sig)-1]) {
		t.Fatal("should fail with truncated signature")
	}

	// Empty signature
	if pk.VerifySignature(msg, nil) {
		t.Fatal("should fail with nil signature")
	}
	if pk.VerifySignature(msg, []byte{}) {
		t.Fatal("should fail with empty signature")
	}

	// Random garbage signature
	garbage := make([]byte, len(sig))
	for i := range garbage {
		garbage[i] = 0xAB
	}
	if pk.VerifySignature(msg, garbage) {
		t.Fatal("should fail with garbage signature")
	}

	// Wrong key verifying valid signature
	sk2, _ := GenerateKey()
	pk2 := sk2.PubKey()
	if pk2.VerifySignature(msg, sig) {
		t.Fatal("wrong key should not verify")
	}
}

func TestSignWithCorruptedPrivKey(t *testing.T) {
	corrupted := &GrumpkinPrivKey{Key: make([]byte, PrivKeySize)}
	for i := range corrupted.Key {
		corrupted.Key[i] = 0xff
	}
	_, err := corrupted.Sign([]byte("test"))
	if err == nil {
		t.Fatal("Sign should fail with corrupted key")
	}
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

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

func TestAddressDeterministic(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pk := sk.PubKey()
	addr1 := pk.Address()
	addr2 := pk.Address()
	if !bytes.Equal(addr1, addr2) {
		t.Fatal("Address should be deterministic")
	}
}

func TestAddressInvalidLength(t *testing.T) {
	pk := &GrumpkinPubKey{Key: []byte{1, 2, 3}}
	if pk.Address() != nil {
		t.Fatal("Address should return nil for invalid key length")
	}
}

func TestAddressUniquePerKey(t *testing.T) {
	sk1, _ := GenerateKey()
	sk2, _ := GenerateKey()
	addr1 := sk1.PubKey().Address()
	addr2 := sk2.PubKey().Address()
	if bytes.Equal(addr1, addr2) {
		t.Fatal("different keys should produce different addresses")
	}
}

// ---------------------------------------------------------------------------
// PubKey / PubKeyE from corrupted key
// ---------------------------------------------------------------------------

func TestPubKeyReturnsNilOnCorruptedKey(t *testing.T) {
	corrupted := &GrumpkinPrivKey{Key: make([]byte, PrivKeySize)}
	for i := range corrupted.Key {
		corrupted.Key[i] = 0xff
	}
	pk := corrupted.PubKey()
	if pk != nil {
		t.Fatal("PubKey() should return nil for corrupted key material")
	}
}

func TestPubKeyEReturnsErrorOnCorruptedKey(t *testing.T) {
	corrupted := &GrumpkinPrivKey{Key: make([]byte, PrivKeySize)}
	for i := range corrupted.Key {
		corrupted.Key[i] = 0xff
	}
	_, err := corrupted.PubKeyE()
	if err == nil {
		t.Fatal("PubKeyE() should return error for corrupted key material")
	}
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

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

func TestPubKeyResetNoOp(t *testing.T) {
	sk, _ := GenerateKey()
	pk := sk.PubKey().(*GrumpkinPubKey)
	before := make([]byte, len(pk.Key))
	copy(before, pk.Key)
	pk.Reset()
	if !bytes.Equal(pk.Key, before) {
		t.Fatal("PubKey.Reset() should be a no-op")
	}
}

// ---------------------------------------------------------------------------
// Bytes returns copy
// ---------------------------------------------------------------------------

func TestBytesReturnsCopy(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	bz := sk.Bytes()
	bz[0] ^= 0xff
	if bz[0] == sk.Key[0] {
		t.Fatal("PrivKey.Bytes() returned a mutable reference")
	}

	pk := sk.PubKey().(*GrumpkinPubKey)
	pbz := pk.Bytes()
	pbz[0] ^= 0xff
	if pbz[0] == pk.Key[0] {
		t.Fatal("PubKey.Bytes() returned a mutable reference")
	}
}

// ---------------------------------------------------------------------------
// Equals
// ---------------------------------------------------------------------------

func TestPubKeyEqualsNonGrumpkin(t *testing.T) {
	sk, _ := GenerateKey()
	pk := sk.PubKey()
	// Compare with a mock non-Grumpkin key
	if pk.Equals(mockPubKey{}) {
		t.Fatal("Equals should return false for non-Grumpkin key")
	}
}

func TestPrivKeyEqualsNonGrumpkin(t *testing.T) {
	sk, _ := GenerateKey()
	if sk.Equals(mockPrivKey{}) {
		t.Fatal("Equals should return false for non-Grumpkin key")
	}
}

func TestPubKeyEqualsDifferentKeys(t *testing.T) {
	sk1, _ := GenerateKey()
	sk2, _ := GenerateKey()
	if sk1.PubKey().Equals(sk2.PubKey()) {
		t.Fatal("different pubkeys should not be equal")
	}
}

func TestPrivKeyEqualsDifferentKeys(t *testing.T) {
	sk1, _ := GenerateKey()
	sk2, _ := GenerateKey()
	if sk1.Equals(sk2) {
		t.Fatal("different privkeys should not be equal")
	}
}

// ---------------------------------------------------------------------------
// Type / String / ProtoMessage
// ---------------------------------------------------------------------------

func TestTypeAndString(t *testing.T) {
	sk, _ := GenerateKey()
	pk := sk.PubKey().(*GrumpkinPubKey)

	if sk.Type() != KeyType {
		t.Fatalf("privkey Type() = %q, want %q", sk.Type(), KeyType)
	}
	if pk.Type() != KeyType {
		t.Fatalf("pubkey Type() = %q, want %q", pk.Type(), KeyType)
	}

	if sk.String() != "GrumpkinPrivKey{...}" {
		t.Fatalf("privkey String() leaked key material: %s", sk.String())
	}
	if len(pk.String()) == 0 {
		t.Fatal("pubkey String() is empty")
	}

	// ProtoMessage should not panic
	sk.ProtoMessage()
	pk.ProtoMessage()
}

// ---------------------------------------------------------------------------
// Algo
// ---------------------------------------------------------------------------

func TestAlgoName(t *testing.T) {
	if GrumpkinAlgo.Name() != "grumpkin" {
		t.Fatalf("algo Name() = %q, want %q", GrumpkinAlgo.Name(), "grumpkin")
	}
}

func TestAlgoDerive(t *testing.T) {
	deriveFn := GrumpkinAlgo.Derive()
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	hdPath := "m/44'/118'/0'/0/0"

	bz, err := deriveFn(mnemonic, "", hdPath)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(bz) != PrivKeySize {
		t.Fatalf("derived key length = %d, want %d", len(bz), PrivKeySize)
	}

	// Deterministic — same mnemonic produces same key
	bz2, err := deriveFn(mnemonic, "", hdPath)
	if err != nil {
		t.Fatalf("Derive 2: %v", err)
	}
	if !bytes.Equal(bz, bz2) {
		t.Fatal("derivation should be deterministic")
	}

	// Different mnemonic produces different key
	mnemonic2 := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
	bz3, err := deriveFn(mnemonic2, "", hdPath)
	if err != nil {
		t.Fatalf("Derive 3: %v", err)
	}
	if bytes.Equal(bz, bz3) {
		t.Fatal("different mnemonics should produce different keys")
	}

	// Different passphrase produces different key
	bz4, err := deriveFn(mnemonic, "passphrase", hdPath)
	if err != nil {
		t.Fatalf("Derive 4: %v", err)
	}
	if bytes.Equal(bz, bz4) {
		t.Fatal("different passphrases should produce different keys")
	}
}

func TestAlgoDeriveInvalidMnemonic(t *testing.T) {
	deriveFn := GrumpkinAlgo.Derive()
	_, err := deriveFn("not a valid mnemonic", "", "m/44'/118'/0'/0/0")
	if err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}

func TestAlgoGenerate(t *testing.T) {
	sk, _ := GenerateKey()
	genFn := GrumpkinAlgo.Generate()

	// Valid input
	result := genFn(sk.Key)
	if result == nil {
		t.Fatal("Generate returned nil for valid input")
	}
	resultSK := result.(*GrumpkinPrivKey)
	if !sk.Equals(resultSK) {
		t.Fatal("generated key should equal input")
	}

	// Wrong length — returns nil instead of panicking
	result = genFn([]byte{1, 2, 3})
	if result != nil {
		t.Fatal("Generate should return nil for wrong length")
	}

	// Nil input
	result = genFn(nil)
	if result != nil {
		t.Fatal("Generate should return nil for nil input")
	}
}

func TestAlgoDeriveAndGenerate(t *testing.T) {
	deriveFn := GrumpkinAlgo.Derive()
	genFn := GrumpkinAlgo.Generate()

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	bz, err := deriveFn(mnemonic, "", "m/44'/118'/0'/0/0")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	// Generate should produce a working key from derived bytes
	result := genFn(bz)
	if result == nil {
		t.Fatal("Generate returned nil")
	}
	sk := result.(*GrumpkinPrivKey)
	sig, err := sk.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !sk.PubKey().VerifySignature([]byte("test"), sig) {
		t.Fatal("derived key should produce valid signatures")
	}
}

// ---------------------------------------------------------------------------
// Codec registration
// ---------------------------------------------------------------------------

func TestRegisterLegacyAminoCodec(t *testing.T) {
	cdc := codec.NewLegacyAmino()
	// Should not panic
	RegisterLegacyAminoCodec(cdc)
}

func TestRegisterInterfaces(t *testing.T) {
	registry := cdctypes.NewInterfaceRegistry()
	// Should not panic
	RegisterInterfaces(registry)
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestConcurrentSignVerify(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pk := sk.PubKey()

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan string, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			msg := []byte("concurrent test message")
			sig, err := sk.Sign(msg)
			if err != nil {
				errs <- "Sign failed"
				return
			}
			if !pk.VerifySignature(msg, sig) {
				errs <- "VerifySignature failed"
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Fatal(e)
	}
}

func TestConcurrentKeyGeneration(t *testing.T) {
	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	keys := make(chan []byte, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sk, err := GenerateKey()
			if err != nil {
				t.Errorf("GenerateKey: %v", err)
				return
			}
			keys <- sk.Bytes()
		}()
	}
	wg.Wait()
	close(keys)

	// Verify all keys are unique
	seen := make(map[string]bool)
	for k := range keys {
		s := string(k)
		if seen[s] {
			t.Fatal("duplicate key generated concurrently")
		}
		seen[s] = true
	}
}

func TestConcurrentAddressDerivation(t *testing.T) {
	sk, _ := GenerateKey()
	pk := sk.PubKey().(*GrumpkinPubKey)
	expected := pk.Address()

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			addr := pk.Address()
			if !bytes.Equal(addr, expected) {
				t.Errorf("concurrent Address() produced different result")
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Edge cases: boundary conditions
// ---------------------------------------------------------------------------

func TestSignVerifyMultipleMessages(t *testing.T) {
	sk, _ := GenerateKey()
	pk := sk.PubKey()

	// Use messages long enough to be unambiguous under gnark ECDSA hashing
	messages := [][]byte{
		[]byte("message alpha"),
		[]byte("message bravo"),
		bytes.Repeat([]byte{0xBB}, 32),
		bytes.Repeat([]byte{0xCC}, 64),
		bytes.Repeat([]byte{0xDD}, 256),
	}

	sigs := make([][]byte, len(messages))
	for i, msg := range messages {
		sig, err := sk.Sign(msg)
		if err != nil {
			t.Fatalf("Sign message %d: %v", i, err)
		}
		if !pk.VerifySignature(msg, sig) {
			t.Fatalf("verify message %d failed", i)
		}
		sigs[i] = sig
	}

	// Cross-verify: signature for msg[i] should not verify for msg[j]
	for i := 1; i < len(messages); i++ {
		if pk.VerifySignature(messages[i-1], sigs[i]) {
			t.Fatalf("signature for message %d should not verify for message %d", i, i-1)
		}
	}
}

func TestPrivKeyFromScalar(t *testing.T) {
	// Test with scalar = 1 (the generator point)
	var one fr.Element
	one.SetUint64(1)
	key, err := privKeyFromScalar(one)
	if err != nil {
		t.Fatalf("privKeyFromScalar(1): %v", err)
	}
	if len(key) != PrivKeySize {
		t.Fatalf("expected %d bytes, got %d", PrivKeySize, len(key))
	}

	// The resulting key should produce valid signatures
	sk := &GrumpkinPrivKey{Key: key}
	sig, err := sk.Sign([]byte("test"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !sk.PubKey().VerifySignature([]byte("test"), sig) {
		t.Fatal("scalar=1 key should produce valid signatures")
	}
}

// ---------------------------------------------------------------------------
// Mock types for Equals testing
// ---------------------------------------------------------------------------

type mockPubKey struct{}

func (mockPubKey) Bytes() []byte                          { return nil }
func (mockPubKey) Address() cryptotypes.Address           { return nil }
func (mockPubKey) VerifySignature(msg, sig []byte) bool   { return false }
func (mockPubKey) Equals(other cryptotypes.PubKey) bool   { return false }
func (mockPubKey) Type() string                           { return "mock" }
func (mockPubKey) String() string                         { return "mock" }
func (mockPubKey) Reset()                                 {}
func (mockPubKey) ProtoMessage()                          {}

type mockPrivKey struct{}

func (mockPrivKey) Bytes() []byte                              { return nil }
func (mockPrivKey) Sign(msg []byte) ([]byte, error)            { return nil, nil }
func (mockPrivKey) PubKey() cryptotypes.PubKey                 { return nil }
func (mockPrivKey) Equals(other cryptotypes.LedgerPrivKey) bool { return false }
func (mockPrivKey) Type() string                               { return "mock" }
func (mockPrivKey) String() string                             { return "mock" }
func (mockPrivKey) Reset()                                     {}
func (mockPrivKey) ProtoMessage()                              {}
