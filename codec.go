package grumpkin

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// RegisterLegacyAminoCodec registers the Grumpkin key types with the Amino
// codec for legacy compatibility.
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&GrumpkinPubKey{}, PubKeyName, nil)
	cdc.RegisterConcrete(&GrumpkinPrivKey{}, "nix/GrumpkinPrivKey", nil)
}

// RegisterInterfaces registers the Grumpkin key types with the Cosmos SDK
// interface registry so they can be used with Protobuf Any encoding.
func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*cryptotypes.PubKey)(nil), &GrumpkinPubKey{})
	registry.RegisterImplementations((*cryptotypes.PrivKey)(nil), &GrumpkinPrivKey{})
}
