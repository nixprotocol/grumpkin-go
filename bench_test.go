package grumpkin

import (
	"testing"
)

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sk.Sign(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for verification")
	sig, err := sk.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !pk.VerifySignature(msg, sig) {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkAddress(b *testing.B) {
	sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.PubKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := pk.Address()
		if addr == nil {
			b.Fatal("nil address")
		}
	}
}

func BenchmarkPubKeyDerivation(b *testing.B) {
	sk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk := sk.PubKey()
		if pk == nil {
			b.Fatal("nil pubkey")
		}
	}
}
