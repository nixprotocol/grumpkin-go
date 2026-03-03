# grumpkin-go

Grumpkin elliptic-curve key types for [Cosmos SDK](https://github.com/cosmos/cosmos-sdk) chains.

The [Grumpkin curve](https://hackmd.io/@aztec-network/ByzgNxBfd) is the cycle-companion of BN254 and is widely used in zero-knowledge proof systems (Noir/Barretenberg, Halo2, etc.). This library provides `cryptotypes.PubKey` and `cryptotypes.LedgerPrivKey` implementations so Grumpkin keys work natively with the Cosmos SDK keyring, codec, and transaction signing pipeline.

Addresses are derived via **Poseidon2(pk.X, pk.Y)** truncated to 20 bytes, giving ZK-friendly address derivation instead of SHA-256/RIPEMD-160.

## Installation

```bash
go get github.com/nixprotocol/grumpkin-go
```

## Usage

```go
package main

import (
    "fmt"

    grumpkin "github.com/nixprotocol/grumpkin-go"
)

func main() {
    // Generate a new key pair
    sk, err := grumpkin.GenerateKey()
    if err != nil {
        panic(err)
    }

    // Derive public key and address
    pk := sk.PubKey()
    addr := pk.Address()
    fmt.Printf("Address: %X\n", addr)

    // Sign and verify
    msg := []byte("hello")
    sig, err := sk.Sign(msg)
    if err != nil {
        panic(err)
    }
    fmt.Println("Valid:", pk.VerifySignature(msg, sig))
}
```

## API

| Function / Type | Description |
|---|---|
| `GenerateKey() (*GrumpkinPrivKey, error)` | Generate a new random Grumpkin private key |
| `NewGrumpkinPubKey(key []byte) (*GrumpkinPubKey, error)` | Create pubkey from bytes (returns error on invalid input) |
| `MustNewGrumpkinPubKey(key []byte) *GrumpkinPubKey` | Create pubkey from bytes (panics on invalid input) |
| `NewGrumpkinPrivKey(key []byte) (*GrumpkinPrivKey, error)` | Create privkey from bytes (returns error on invalid length) |
| `MustNewGrumpkinPrivKey(key []byte) *GrumpkinPrivKey` | Create privkey from bytes (panics on invalid length) |
| `GrumpkinPubKey` | Implements `cryptotypes.PubKey` — `Address()`, `Bytes()`, `VerifySignature()`, `Equals()`, `Type()` |
| `GrumpkinPrivKey` | Implements `cryptotypes.LedgerPrivKey` — `Sign()`, `PubKey()`, `PubKeyE()`, `Bytes()`, `Equals()`, `Type()`, `Reset()` |
| `RegisterInterfaces(registry)` | Register key types with Cosmos SDK Protobuf interface registry |
| `RegisterLegacyAminoCodec(cdc)` | Register key types with Amino codec |
| `GrumpkinAlgo` | `keyring.SignatureAlgo` for BIP-39 mnemonic derivation |

## Key Format

| Field | Size | Description |
|---|---|---|
| **PubKey** | 64 bytes | Raw X (32) \|\| Y (32), uncompressed |
| **PrivKey** | 64 bytes | Compressed pubkey (32) \|\| scalar (32) |
| **Address** | 20 bytes | Poseidon2(X, Y)[12:32] |

## Integration Guide

### 1. Register key types at app startup

In your Cosmos SDK `app.go`:

```go
import grumpkin "github.com/nixprotocol/grumpkin-go"

func init() {
    // Amino (legacy)
    grumpkin.RegisterLegacyAminoCodec(codec.NewLegacyAmino())
    // Protobuf
    grumpkin.RegisterInterfaces(cdctypes.NewInterfaceRegistry())
}
```

### 2. Configure the keyring algorithm

Register `GrumpkinAlgo` so the keyring can derive Grumpkin keys from BIP-39 mnemonics:

```go
kr, err := keyring.New("myapp", keyring.BackendFile, homeDir, os.Stdin,
    cdc, func(options *keyring.Options) {
        options.SupportedAlgos = keyring.SigningAlgoList{grumpkin.GrumpkinAlgo}
        options.SupportedAlgosLedger = keyring.SigningAlgoList{grumpkin.GrumpkinAlgo}
    },
)
```

### 3. Error handling

All constructors return errors. Use `Must*` variants only in tests or with pre-validated data:

```go
// Production code — handle errors
pk, err := grumpkin.NewGrumpkinPubKey(rawBytes)
if err != nil {
    return fmt.Errorf("invalid pubkey: %w", err)
}

// Test code — panics are acceptable
pk := grumpkin.MustNewGrumpkinPubKey(rawBytes)
```

### 4. Safe public key derivation

`PubKey()` returns `nil` (not panic) if key material is corrupted. For explicit error handling use `PubKeyE()`:

```go
pk, err := sk.PubKeyE()
if err != nil {
    return fmt.Errorf("corrupted key: %w", err)
}
```

## Threat Model

### What this library does

- **Key generation**: Produces Grumpkin ECDSA key pairs using `crypto/rand`
- **Signing**: Signs arbitrary messages using gnark-crypto's Grumpkin ECDSA
- **Verification**: Verifies signatures against Grumpkin public keys
- **Address derivation**: Computes Poseidon2-based 20-byte addresses
- **Codec integration**: Registers types with Cosmos SDK Amino and Protobuf codecs

### Trust boundaries

| Input | Trust level | Validation |
|---|---|---|
| Key bytes from keyring/DB | Trusted (your own storage) | Length check; `PubKey()` returns nil on deserialization failure |
| Key bytes from network/user | Untrusted | Full curve-point validation via `NewGrumpkinPubKey()` |
| Messages to sign | Trusted (your own data) | None required — ECDSA signs arbitrary bytes |
| Signatures to verify | Untrusted | `VerifySignature()` returns `false` for any malformed input |

### Assumptions

- **RNG quality**: Key generation depends on `crypto/rand`. A compromised or low-entropy RNG breaks all security guarantees.
- **gnark-crypto correctness**: Curve arithmetic and ECDSA are delegated to [gnark-crypto](https://github.com/consensys/gnark-crypto), a widely-audited library.
- **Poseidon2 collision resistance**: Address derivation relies on [poseidon2-go](https://github.com/nixprotocol/poseidon2-go) being collision-resistant over the BN254 scalar field.
- **No side-channel hardening**: This library does not claim constant-time scalar multiplication beyond what gnark-crypto provides. Do not use in environments where timing or power analysis is a threat.

### Out of scope

- Key storage / encryption at rest (use Cosmos SDK keyring)
- Transport security (use TLS / authenticated channels)
- Multi-party key generation or threshold signatures
- Post-quantum security

## Security Best Practices

1. **Always call `Reset()`** on private keys when done to zero memory:
   ```go
   sk, _ := grumpkin.GenerateKey()
   defer sk.Reset()
   ```

2. **Validate untrusted public keys** using the error-returning constructor:
   ```go
   pk, err := grumpkin.NewGrumpkinPubKey(untrustedBytes)
   ```

3. **Check `PubKey()` return value** — it returns `nil` for corrupted keys instead of panicking.

4. **Don't reuse nonces** — this library uses gnark-crypto's deterministic ECDSA (RFC 6979-style), so nonce reuse is not a concern under normal operation.

5. **Pin gnark-crypto version** — Grumpkin curve parameters are fixed, but implementation bugs could affect security. Pin to tested versions.

## Performance

Benchmarks on Apple M1 Pro:

| Operation | Time | Allocs |
|---|---|---|
| Key generation | ~53 µs | 14 |
| Sign | ~69 µs | 35 |
| Verify | ~84 µs | 25 |
| Address derivation | ~10 µs | 1 |
| PubKey derivation | ~10 µs | 2 |

Run benchmarks yourself:

```bash
go test -bench=. -benchmem
```

## Testing

```bash
# Unit tests (97%+ coverage)
go test -v ./...

# Coverage report
go test -coverprofile=cover.out ./... && go tool cover -html=cover.out

# Fuzz testing (run for at least 30s)
go test -fuzz=FuzzVerifySignature -fuzztime=30s
go test -fuzz=FuzzSign -fuzztime=30s
go test -fuzz=FuzzKeyDeserialization -fuzztime=30s
go test -fuzz=FuzzNewGrumpkinPubKey -fuzztime=30s
go test -fuzz=FuzzAddressDerivation -fuzztime=30s

# Benchmarks
go test -bench=. -benchmem
```

## Dependencies

- [`gnark-crypto`](https://github.com/consensys/gnark-crypto) — Grumpkin curve arithmetic and ECDSA
- [`cosmos-sdk`](https://github.com/cosmos/cosmos-sdk) — `cryptotypes`, `keyring`, `codec`, `hd`
- [`poseidon2-go`](https://github.com/nixprotocol/poseidon2-go) — Poseidon2 hash for address derivation

## License

Apache 2.0 — See [LICENSE](LICENSE).

## Author

[NixProtocol](https://nixprotocol.com) ([GitHub](https://github.com/nixprotocol))
