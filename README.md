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
| `NewGrumpkinPubKey(key []byte) *GrumpkinPubKey` | Create pubkey from validated bytes (panics on invalid input) |
| `NewGrumpkinPubKeyFromBytes(key []byte) (*GrumpkinPubKey, error)` | Create pubkey from bytes (returns error on invalid input) |
| `NewGrumpkinPrivKey(key []byte) *GrumpkinPrivKey` | Create privkey from bytes (panics on invalid length) |
| `NewGrumpkinPrivKeyFromBytes(key []byte) (*GrumpkinPrivKey, error)` | Create privkey from bytes (returns error on invalid length) |
| `GrumpkinPubKey` | Implements `cryptotypes.PubKey` — `Address()`, `Bytes()`, `VerifySignature()`, `Equals()`, `Type()` |
| `GrumpkinPrivKey` | Implements `cryptotypes.LedgerPrivKey` — `Sign()`, `PubKey()`, `Bytes()`, `Equals()`, `Type()`, `Reset()` |
| `RegisterInterfaces(registry)` | Register key types with Cosmos SDK Protobuf interface registry |
| `RegisterLegacyAminoCodec(cdc)` | Register key types with Amino codec |
| `GrumpkinAlgo` | `keyring.SignatureAlgo` for BIP-39 mnemonic derivation |

## Key Format

| Field | Size | Description |
|---|---|---|
| **PubKey** | 64 bytes | Raw X (32) \|\| Y (32), uncompressed |
| **PrivKey** | 64 bytes | Compressed pubkey (32) \|\| scalar (32) |
| **Address** | 20 bytes | Poseidon2(X, Y)[12:32] |

## Dependencies

- [`gnark-crypto`](https://github.com/consensys/gnark-crypto) — Grumpkin curve arithmetic and ECDSA
- [`cosmos-sdk`](https://github.com/cosmos/cosmos-sdk) — `cryptotypes`, `keyring`, `codec`, `hd`
- [`poseidon2-go`](https://github.com/nixprotocol/poseidon2-go) — Poseidon2 hash for address derivation

## License

Apache 2.0 — See [LICENSE](LICENSE).

## Author

[NixProtocol](https://nixprotocol.com) ([GitHub](https://github.com/nixprotocol))
