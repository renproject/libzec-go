package libzec

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/iqoption/zecutil"
	"github.com/renproject/libzec-go/clients"
	"github.com/renproject/libzec-go/errors"
)

type Client interface {
	clients.ClientCore

	// Balance of the given address on ZCash blockchain.
	Balance(address string, confirmations int64) (int64, error)

	// FormatTransactionView formats the message and txhash into a user friendly
	// message.
	FormatTransactionView(msg, txhash string) string

	// SerializePublicKey serializes the given public key.
	SerializePublicKey(pubKey *btcec.PublicKey) ([]byte, error)

	// PublicKeyToAddress converts the public key to a zcash address.
	PublicKeyToAddress(pubKeyBytes []byte) (btcutil.Address, error)

	// SlaveAddress creates an a deterministic unique address that can be spent
	// by the private key correspndong to the given master public key hash
	SlaveAddress(mpkh, nonce []byte) (btcutil.Address, error)

	// SlaveScript creates a deterministic unique script that can be spent by
	// the private key correspndong to the given master public key hash
	SlaveScript(mpkh, nonce []byte) ([]byte, error)

	// UTXOCount returns the number of utxos that can be spent.
	UTXOCount(address string, confirmations int64) (int, error)

	// Validate returns whether an address is valid or not
	Validate(address string) error
}

type client struct {
	clients.ClientCore
}

func (client *client) Balance(address string, confirmations int64) (int64, error) {
	utxos, err := client.GetUTXOs(address, 999999, confirmations)
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
		return fmt.Sprintf("%s, transaction can be viewed at https://chain.so/tx/ZEC/%s", msg, txhash)
	case "testnet3":
		return fmt.Sprintf("%s, transaction can be viewed at https://chain.so/tx/ZECTEST/%s", msg, txhash)
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
	return AddressFromHash160(hash20, client.NetworkParams(), false)
}

func (client *client) UTXOCount(address string, confirmations int64) (int, error) {
	utxos, err := client.GetUTXOs(address, 999999, confirmations)
	if err != nil {
		return 0, err
	}
	return len(utxos), nil
}

func (client *client) Validate(address string) error {
	_, err := zecutil.DecodeAddress(address, client.NetworkParams().Name)
	return err
}

func (client *client) SlaveAddress(mpkh, nonce []byte) (btcutil.Address, error) {
	script, err := client.SlaveScript(mpkh, nonce)
	if err != nil {
		return nil, nil
	}
	scriptHash := [20]byte{}
	copy(scriptHash[:], btcutil.Hash160(script))
	return AddressFromHash160(scriptHash, client.NetworkParams(), true)
}

func (client *client) SlaveScript(mpkh, nonce []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(nonce)
	b.AddOp(txscript.OP_DROP)
	b.AddOp(txscript.OP_DUP)
	b.AddOp(txscript.OP_HASH160)
	b.AddData(mpkh)
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddOp(txscript.OP_CHECKSIG)
	return b.Script()
}
func NewMercuryClient(network string) (Client, error) {
	core, err := clients.NewMercuryClientCore(network)
	if err != nil {
		return nil, err
	}
	return &client{core}, nil
}

func NewChainSoClient(network string) (Client, error) {
	core, err := clients.NewChainSoClientCore(network)
	if err != nil {
		return nil, err
	}
	return &client{core}, nil
}
