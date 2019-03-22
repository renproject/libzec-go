package libzec

import (
	"context"
	"fmt"

	"github.com/iqoption/zecutil"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/renproject/libzec-go/clients"
	"github.com/renproject/libzec-go/errors"
)

type Client interface {
	clients.ClientCore

	// Balance of the given address on ZCash blockchain.
	Balance(ctx context.Context, address string, confirmations int64) (int64, error)

	// FormatTransactionView formats the message and txhash into a user friendly
	// message.
	FormatTransactionView(msg, txhash string) string

	// SerializePublicKey serializes the given public key.
	SerializePublicKey(pubKey *btcec.PublicKey) ([]byte, error)

	// PublicKeyToAddress converts the public key to a zcash address.
	PublicKeyToAddress(pubKeyBytes []byte) (btcutil.Address, error)
}

type client struct {
	clients.ClientCore
}

func (client *client) Balance(ctx context.Context, address string, confirmations int64) (int64, error) {
	utxos, err := client.GetUTXOs(ctx, address, 999999, confirmations)
	if err != nil {
		return 0, err
	}
	var balance int64
	for _, utxo := range utxos {
		balance = balance + utxo.Amount
	}
	return balance, nil
}

func (client *client) FormatTransactionView(msg, txhash string) string {
	switch client.NetworkParams().Name {
	case "mainnet":
		return fmt.Sprintf("%s, transaction can be viewed at https://live.blockcypher.com/btc/tx/%s", msg, txhash)
	case "testnet3":
		return fmt.Sprintf("%s, transaction can be viewed at https://live.blockcypher.com/btc-testnet/tx/%s", msg, txhash)
	default:
		return ""
	}
}

func (client *client) SerializePublicKey(pubKey *btcec.PublicKey) ([]byte, error) {
	net := client.NetworkParams()
	switch net {
	case &chaincfg.MainNetParams:
		return pubKey.SerializeCompressed(), nil
	case &chaincfg.TestNet3Params:
		return pubKey.SerializeUncompressed(), nil
	default:
		return nil, errors.NewErrUnsupportedNetwork(net.Name)
	}
}

func (client *client) PublicKeyToAddress(pubKeyBytes []byte) (btcutil.Address, error) {
	hash20 := [20]byte{}
	copy(hash20[:], btcutil.Hash160(pubKeyBytes))
	return zecutil.NewAddressPubKeyHash(hash20, client.NetworkParams().Name), nil
}

func NewMercuryClient(network string) (Client, error) {
	core, err := clients.NewMercuryClientCore(network)
	if err != nil {
		return nil, err
	}
	return &client{core}, nil
}
