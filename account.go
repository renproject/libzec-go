package libzec

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/sirupsen/logrus"
)

// The TxExecutionSpeed indicates the tier of speed that the transaction falls
// under while writing to the blockchain.
type TxExecutionSpeed uint8

// TxExecutionSpeed values.
const (
	Nil = TxExecutionSpeed(iota)
	Slow
	Standard
	Fast
)

type account struct {
	PrivKey *btcec.PrivateKey
	Logger  logrus.FieldLogger
	Client
}

// Account is an ZCash external account that can sign and submit transactions
// to the ZCash blockchain. An Account is an abstraction over the ZCash
// blockchain.
type Account interface {
	Client
	BTCClient() Client
	Address() (btcutil.Address, error)
	SerializedPublicKey() ([]byte, error)
	Transfer(ctx context.Context, to string, value int64, speed TxExecutionSpeed, sendAll bool) (string, int64, error)
	SendTransaction(
		ctx context.Context,
		script []byte,
		speed TxExecutionSpeed,
		updateTxIn func(*wire.TxIn),
		preCond func(*wire.MsgTx) bool,
		f func(*txscript.ScriptBuilder),
		postCond func(*wire.MsgTx) bool,
		sendAll bool,
	) (string, int64, error)
}

// NewAccount returns a user account for the provided private key which is
// connected to a ZCash client.
func NewAccount(client Client, privateKey *ecdsa.PrivateKey, logger logrus.FieldLogger) Account {
	if logger == nil {
		nullLogger := logrus.New()
		logFile, err := os.OpenFile(os.DevNull, os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			panic(err)
		}
		nullLogger.SetOutput(logFile)
		logger = nullLogger
	}
	return &account{
		(*btcec.PrivateKey)(privateKey),
		logger,
		client,
	}
}

// Address returns the address of the given private key
func (account *account) Address() (btcutil.Address, error) {
	pubKeyBytes, err := account.SerializedPublicKey()
	if err != nil {
		return nil, err
	}
	return account.PublicKeyToAddress(pubKeyBytes)
}

// Transfer zcash to the given address
func (account *account) Transfer(ctx context.Context, to string, value int64, speed TxExecutionSpeed, sendAll bool) (string, int64, error) {
	if sendAll {
		me, err := account.Address()
		if err != nil {
			return "", 0, err
		}
		balance, err := account.Balance(ctx, me.EncodeAddress(), 0)
		if err != nil {
			return "", 0, err
		}
		value = balance
	}

	address, err := DecodeAddress(to, account.NetworkParams())
	if err != nil {
		return "", 0, err
	}
	return account.SendTransaction(
		ctx,
		nil,
		speed,
		nil,
		func(tx *wire.MsgTx) bool {
			P2PKHScript, err := PayToAddrScript(address)
			if err != nil {
				return false
			}
			tx.AddTxOut(wire.NewTxOut(value, P2PKHScript))
			return true
		},
		nil,
		nil,
		sendAll,
	)
}

// SendTransaction builds, signs, verifies and publishes a transaction to the
// corresponding blockchain. If contract is provided then the transaction uses
// the contract's unspent outputs for the transaction, otherwise uses the
// account's unspent outputs to fund the transaction. preCond is executed in
// the starting of the process, if it returns false SendTransaction returns
// ErrPreConditionCheckFailed and stops the process. This function can be used
// to modify how the unspent outputs are spent, this can be nil. f is supposed
// to be used with non empty contracts, to modify the signature script. preCond
// is executed in the starting of the process, if it returns false
// SendTransaction returns ErrPreConditionCheckFailed and stops the process.
func (account *account) SendTransaction(
	ctx context.Context,
	contract []byte,
	speed TxExecutionSpeed,
	updateTxIn func(*wire.TxIn),
	preCond func(*wire.MsgTx) bool,
	f func(*txscript.ScriptBuilder),
	postCond func(*wire.MsgTx) bool,
	sendAll bool,
) (string, int64, error) {
	// Current ZCash Transaction Version (Sapling: 4) .
	tx := account.newTx(ctx, wire.NewMsgTx(4))
	if preCond != nil && !preCond(tx.msgTx.MsgTx) {
		return "", 0, ErrPreConditionCheckFailed
	}

	var address btcutil.Address
	var err error
	if contract == nil {
		address, err = account.Address()
		if err != nil {
			return "", 0, err
		}
	} else {
		hash20 := [20]byte{}
		copy(hash20[:], btcutil.Hash160(contract))
		address, err = AddressFromHash160(hash20, account.NetworkParams(), true)
		if err != nil {
			return "", 0, err
		}
	}

	account.Logger.Infof("funding %s, with fee %d SAT/byte", address.EncodeAddress(), speed)
	if sendAll {
		if err := tx.fundAll(address); err != nil {
			return "", 0, err
		}
	} else {
		if err := tx.fund(address); err != nil {
			return "", 0, err
		}
	}
	account.Logger.Info("successfully funded the transaction")

	txFee := MaxZCashFee
	tx.msgTx.TxOut[len(tx.msgTx.TxOut)-1].Value -= txFee

	account.Logger.Info("signing the tx")
	if err := tx.sign(f, updateTxIn, contract); err != nil {
		return "", 0, err
	}
	account.Logger.Info("successfully signined the tx")

	for {
		account.Logger.Info("trying to submit the tx")
		select {
		case <-ctx.Done():
			account.Logger.Info("submitting failed due to failed post condition")
			return "", 0, ErrPostConditionCheckFailed
		default:
			if err := tx.submit(); err != nil {
				account.Logger.Infof("submitting failed due to %s", err)
				return "", 0, err
			}
			for i := 0; i < 60; i++ {
				if postCond == nil || postCond(tx.msgTx.MsgTx) {
					account.Logger.Infof("successfully submitted the tx", err)
					return tx.msgTx.TxHash().String(), txFee, nil
				}
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (account *account) SerializedPublicKey() ([]byte, error) {
	return account.SerializePublicKey(account.PrivKey.PubKey())
}

func (account *account) BTCClient() Client {
	return account.Client
}

// SuggestedTxRate returns the gas price that zcashfees.earn.com recommends for
// transactions to be mined on ZCash blockchain based on the speed provided.
func SuggestedTxRate(txSpeed TxExecutionSpeed) (int64, error) {
	request, err := http.NewRequest("GET", "https://zcashfees.earn.com/api/v1/fees/recommended", nil)
	if err != nil {
		return 0, fmt.Errorf("cannot build request to zcashfees.earn.com = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	res, err := (&http.Client{}).Do(request)
	if err != nil {
		return 0, fmt.Errorf("cannot connect to zcashfees.earn.com = %v", err)
	}
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code %v from zcashfees.earn.com", res.StatusCode)
	}

	data := struct {
		Slow     int64 `json:"fastestFee"`
		Standard int64 `json:"halfHourFee"`
		Fast     int64 `json:"hourFee"`
	}{}
	if err = json.NewDecoder(res.Body).Decode(&data); err != nil {
		resp, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("cannot decode response body (%s) from zcashfees.earn.com = %v", resp, err)
	}

	switch txSpeed {
	case Slow:
		return data.Slow, nil
	case Standard:
		return data.Standard, nil
	case Fast:
		return data.Fast, nil
	default:
		return 0, fmt.Errorf("invalid speed tier: %v", txSpeed)
	}
}
