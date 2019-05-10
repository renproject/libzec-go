package libzec

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/iqoption/zecutil"
)

type txBuilder struct {
	version   int32
	fee, dust int64
	client    Client
}

// NewTxBuilder creates a new tx builder.
func NewTxBuilder(client Client) TxBuilder {
	return &txBuilder{2, 10000, 600, client}
}

// The TxBuilder can build txs, that allow the user to extract the hashes to be
// signed.
type TxBuilder interface {
	Build(ctx context.Context, pubKey ecdsa.PublicKey, to string, contract []byte, value int64, mwIns, scriptIns int) (Tx, error)
}

type Tx interface {
	Hashes() [][]byte
	InjectSigs(sigs []*btcec.Signature) error
	Submit(ctx context.Context) ([]byte, error)
}

type transaction struct {
	sent      int64
	msgTx     *zecutil.MsgTx
	hashes    [][]byte
	client    Client
	contract  []byte
	publicKey ecdsa.PublicKey
	mwIns     int
}

func (builder *txBuilder) Build(
	ctx context.Context,
	pubKey ecdsa.PublicKey,
	to string,
	contract []byte,
	value int64,
	mwIns, scriptIns int,
) (Tx, error) {
	pubKeyBytes, err := builder.client.SerializePublicKey((*btcec.PublicKey)(&pubKey))
	if err != nil {
		return nil, err
	}

	from, err := builder.client.PublicKeyToAddress(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	toAddr, err := zecutil.DecodeAddress(to, builder.client.NetworkParams().Name)
	if err != nil {
		return nil, err
	}

	msgTx := &zecutil.MsgTx{
		MsgTx:        wire.NewMsgTx(4),
		ExpiryHeight: ZCashExpiryHeight,
	}

	var sent int64
	var amt int64
	recvVals, pubKeyScript, err := fundZecTx(ctx, from, nil, builder.client, msgTx, mwIns)
	if err != nil {
		return nil, err
	}
	amt = sum(recvVals)

	if contract != nil {
		recvVals2, _, err := fundZecTx(ctx, from, contract, builder.client, msgTx, scriptIns)
		if err != nil {
			return nil, err
		}
		recvVals = append(recvVals, recvVals2...)
		amt2 := sum(recvVals2)
		amt += amt2
		sent = amt2 - builder.fee
	}

	if amt < value+builder.fee {
		return nil, fmt.Errorf("insufficient balance to do the transfer:"+
			"got: %d required: %d", amt, value+builder.fee)
	}

	if len(msgTx.TxIn) != mwIns+scriptIns {
		return nil, fmt.Errorf("utxos spent")
	}

	fmt.Println("utxos being used: ")
	for i, txIn := range msgTx.TxIn {
		fmt.Printf("[%d]: %s\n", i, txIn.PreviousOutPoint.Hash.String())
	}

	if value > 0 {
		sent = value
		script, err := PayToAddrScript(toAddr)
		if err != nil {
			return nil, err
		}
		msgTx.AddTxOut(wire.NewTxOut(value, script))
	}

	if amt-value > builder.fee+600 {
		P2PKHScript, err := PayToAddrScript(from)
		if err != nil {
			return nil, err
		}
		msgTx.AddTxOut(wire.NewTxOut(amt-value-builder.fee, P2PKHScript))
	}

	var hashes [][]byte
	for i := 0; i < mwIns; i++ {
		hash, err := CalcSignatureHash(pubKeyScript, txscript.SigHashAll, msgTx, i, recvVals[i])
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	for i := mwIns; i < mwIns+scriptIns; i++ {
		hash, err := CalcSignatureHash(contract, txscript.SigHashAll, msgTx, i, recvVals[i])
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}

	return &transaction{
		sent:      sent,
		hashes:    hashes,
		msgTx:     msgTx,
		client:    builder.client,
		publicKey: pubKey,
		contract:  contract,
		mwIns:     mwIns,
	}, nil
}

func (tx *transaction) Hashes() [][]byte {
	return tx.hashes
}

func (tx *transaction) InjectSigs(sigs []*btcec.Signature) error {
	pubKey := (*btcec.PublicKey)(&tx.publicKey)
	serializedPublicKey, err := tx.client.SerializePublicKey(pubKey)
	if err != nil {
		return err
	}
	for i, sig := range sigs {
		builder := txscript.NewScriptBuilder()
		builder.AddData(append(sig.Serialize(), byte(txscript.SigHashAll)))
		builder.AddData(serializedPublicKey)
		if i >= tx.mwIns && tx.contract != nil {
			builder.AddData(tx.contract)
		}
		sigScript, err := builder.Script()
		if err != nil {
			return err
		}
		tx.msgTx.TxIn[i].SignatureScript = sigScript
	}
	return nil
}

func (tx *transaction) Submit(ctx context.Context) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := tx.msgTx.ZecEncode(buf, 0, wire.BaseEncoding); err != nil {
		return nil, err
	}
	if err := tx.client.PublishTransaction(ctx, buf.Bytes()); err != nil {
		return nil, err
	}
	return hex.DecodeString(tx.msgTx.TxHash().String())
}

func fundZecTx(ctx context.Context, from btcutil.Address, script []byte, client Client, msgTx *zecutil.MsgTx, n int) ([]int64, []byte, error) {
	receiveValues := make([]int64, n)
	if script != nil {
		script20 := [20]byte{}
		copy(script20[:], btcutil.Hash160(script))
		scriptAddr, err := AddressFromHash160(script20, client.NetworkParams(), true)
		if err != nil {
			return receiveValues, nil, err
		}
		from = scriptAddr
	}

	utxos, err := client.GetUTXOs(ctx, from.EncodeAddress(), int64(n), 0)
	if err != nil {
		return receiveValues, nil, err
	}
	if len(utxos) < n {
		return receiveValues, nil, fmt.Errorf("insufficient utxos requirex: %d got: %d", n, len(utxos))
	}

	var scriptPubKey []byte
	for i, utxo := range utxos {
		ScriptPubKey, err := hex.DecodeString(utxo.ScriptPubKey)
		if err != nil {
			return receiveValues, nil, err
		}
		if len(scriptPubKey) == 0 {
			scriptPubKey = ScriptPubKey
		} else {
			if bytes.Compare(scriptPubKey, ScriptPubKey) != 0 {
				continue
			}
		}

		hash, err := chainhash.NewHashFromStr(utxo.TxHash)
		if err != nil {
			return receiveValues, nil, err
		}
		msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(hash, utxo.Vout), []byte{}, [][]byte{}))
		receiveValues[i] = utxo.Amount
	}

	if script != nil {
		return receiveValues, script, nil
	}
	return receiveValues, scriptPubKey, nil
}

func sum(vals []int64) int64 {
	var res int64
	for _, val := range vals {
		res += val
	}
	return res
}
