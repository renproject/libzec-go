package libzec

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
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
	TxBuilder
}

// Account is an ZCash external account that can sign and submit transactions
// to the ZCash blockchain. An Account is an abstraction over the ZCash
// blockchain.
type Account interface {
	Client
	ZECClient() Client
	Address() (btcutil.Address, error)
	SerializedPublicKey() ([]byte, error)
	Transfer(to string, value int64, sendAll bool) (string, int64, error)
	SendTransaction(to string, contract []byte, value int64, addData func(builder *txscript.ScriptBuilder), sendAll bool) (string, int64, error)
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
		NewTxBuilder(client),
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

// SendTransaction
func (account *account) SendTransaction(to string, contract []byte, value int64, addData func(builder *txscript.ScriptBuilder), sendAll bool) (string, int64, error) {
	return SendTransaction(account.Client, account.PrivKey.PubKey(), to, contract, value, account.PrivKey.Sign, addData, sendAll)
}

// Transfer zcash to the given address
func (account *account) Transfer(to string, value int64, sendAll bool) (string, int64, error) {
	return account.SendTransaction(to, nil, value, nil, sendAll)
}

func (account *account) SerializedPublicKey() ([]byte, error) {
	return account.SerializePublicKey(account.PrivKey.PubKey())
}

func (account *account) ZECClient() Client {
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
