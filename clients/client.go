package clients

import (
	"context"

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

	GetUTXOs(ctx context.Context, address string, limit, confitmations int64) ([]UTXO, error)
	Confirmations(ctx context.Context, txHash string) (int64, error)

	// ScriptFunded checks whether a script is funded.
	ScriptFunded(ctx context.Context, address string, value int64) (bool, int64, error)

	// ScriptRedeemed checks whether a script is redeemed.
	ScriptRedeemed(ctx context.Context, address string, value int64) (bool, int64, error)

	// ScriptSpent checks whether a script is spent.
	ScriptSpent(ctx context.Context, script, spender string) (bool, string, error)

	// PublishTransaction should publish a signed transaction to the ZCash
	// blockchain.
	PublishTransaction(ctx context.Context, signedTransaction []byte) error
}
