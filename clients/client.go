package clients

import (
	"github.com/btcsuite/btcd/chaincfg"
)

type UTXO struct {
	TxHash       string `json:"txHash"`
	Amount       int64  `json:"amount"`
	ScriptPubKey string `json:"scriptPubKey"`
	Vout         uint32 `json:"vout"`
}
type ClientCore interface {
	// NetworkParams should return the network parameters of the underlying
	// ZCash blockchain.
	NetworkParams() *chaincfg.Params

	GetUTXO(txhash string, vout uint32) (UTXO, error)
	GetUTXOs(address string, limit, confitmations int64) ([]UTXO, error)
	Confirmations(txHash string) (int64, error)

	// ScriptFunded checks whether a script is funded.
	ScriptFunded(address string, value int64) (bool, int64, error)

	// ScriptRedeemed checks whether a script is redeemed.
	ScriptRedeemed(address string, value int64) (bool, int64, error)

	// ScriptSpent checks whether a script is spent.
	ScriptSpent(script, spender string) (bool, string, error)

	// PublishTransaction should publish a signed transaction to the ZCash
	// blockchain.
	PublishTransaction(signedTransaction []byte) error
}
