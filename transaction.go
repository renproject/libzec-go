package libzec

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/iqoption/zecutil"
)

const ZCashDust = 5000
const MaxZCashFee = int64(10000)
const ZCashExpiryHeight = 6000000

type tx struct {
	receiveValues   []int64
	scriptPublicKey []byte
	account         *account
	msgTx           *zecutil.MsgTx
}

func (account *account) newTx(msgtx *wire.MsgTx) *tx {
	return &tx{
		msgTx: &zecutil.MsgTx{
			MsgTx:        msgtx,
			ExpiryHeight: ZCashExpiryHeight,
		},
		account: account,
	}
}

func (tx *tx) fund(addr btcutil.Address) error {
	if addr == nil {
		var err error
		addr, err = tx.account.Address()
		if err != nil {
			return err
		}
	}

	var value int64
	for i, j := range tx.msgTx.TxOut {
		if j.Value < 600 {
			return fmt.Errorf("transaction's %d output value (%d) is less than zcash's minimum value (%d)", i, j.Value, ZCashDust)
		}
		value = value + j.Value
	}

	balance, err := tx.account.Balance(addr.EncodeAddress(), 0)
	if err != nil {
		return err
	}

	if value+MaxZCashFee > balance {
		return NewErrInsufficientBalance(addr.EncodeAddress(), value+MaxZCashFee, balance)
	}

	utxos, err := tx.account.GetUTXOs(addr.EncodeAddress(), 999999, 0)
	if err != nil {
		return err
	}

	for _, j := range utxos {
		ScriptPubKey, err := hex.DecodeString(j.ScriptPubKey)
		if err != nil {
			return err
		}
		if len(tx.scriptPublicKey) == 0 {
			tx.scriptPublicKey = ScriptPubKey
		} else {
			if bytes.Compare(tx.scriptPublicKey, ScriptPubKey) != 0 {
				continue
			}
		}
		tx.receiveValues = append(tx.receiveValues, j.Amount)
		hash, err := chainhash.NewHashFromStr(j.TxHash)
		if err != nil {
			return err
		}
		tx.msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(hash, j.Vout), []byte{}, [][]byte{}))
		value = value - j.Amount
		if value <= -MaxZCashFee {
			break
		}
	}

	if value <= -MaxZCashFee {
		P2PKHScript, err := PayToAddrScript(addr)
		if err != nil {
			return err
		}
		tx.msgTx.AddTxOut(wire.NewTxOut(-value, P2PKHScript))
	} else {
		return ErrMismatchedPubKeys
	}
	return nil
}

func (tx *tx) fundAll(addr btcutil.Address) error {
	utxos, err := tx.account.GetUTXOs(addr.EncodeAddress(), 1000, 0)
	if err != nil {
		return err
	}
	for _, j := range utxos {
		ScriptPubKey, err := hex.DecodeString(j.ScriptPubKey)
		if err != nil {
			return err
		}
		if len(tx.scriptPublicKey) == 0 {
			tx.scriptPublicKey = ScriptPubKey
		} else {
			if bytes.Compare(tx.scriptPublicKey, ScriptPubKey) != 0 {
				continue
			}
		}
		tx.receiveValues = append(tx.receiveValues, j.Amount)
		hash, err := chainhash.NewHashFromStr(j.TxHash)
		if err != nil {
			return err
		}
		tx.msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(hash, j.Vout), []byte{}, [][]byte{}))
	}
	return nil
}

func (tx *tx) sign(f func(*txscript.ScriptBuilder), updateTxIn func(*wire.TxIn), contract []byte) error {
	var subScript []byte
	if contract == nil {
		subScript = tx.scriptPublicKey
	} else {
		subScript = contract
	}
	serializedPublicKey, err := tx.account.SerializedPublicKey()
	if err != nil {
		return err
	}

	for i, txin := range tx.msgTx.TxIn {
		if updateTxIn != nil {
			updateTxIn(txin)
		}
		sig, err := zecutil.RawTxInSignature(tx.msgTx, i, subScript, txscript.SigHashAll, tx.account.PrivKey, tx.receiveValues[i])
		if err != nil {
			return err
		}
		builder := txscript.NewScriptBuilder()
		builder.AddData(sig)
		builder.AddData(serializedPublicKey)
		if f != nil {
			f(builder)
		}
		if contract != nil {
			builder.AddData(contract)
		}
		sigScript, err := builder.Script()
		if err != nil {
			return err
		}
		txin.SignatureScript = sigScript
	}
	return nil
}

func (tx *tx) submit() error {
	buf := new(bytes.Buffer)
	if err := tx.msgTx.ZecEncode(buf, 0, wire.BaseEncoding); err != nil {
		return err
	}
	return tx.account.PublishTransaction(buf.Bytes())
}
