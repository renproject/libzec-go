package libzec

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type wallet struct {
	mnemonic string
	client   Client
	logger   logrus.FieldLogger
}

type Wallet interface {
	NewAccount(derivationPath []uint32, password string) (Account, error)
}

func NewWallet(mnemonic string, client Client, logger logrus.FieldLogger) Wallet {
	return &wallet{mnemonic, client, logger}
}

func (wallet *wallet) NewAccount(derivationPath []uint32, password string) (Account, error) {
	seed := bip39.NewSeed(wallet.mnemonic, password)
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	for _, val := range derivationPath {
		key, err = key.NewChildKey(val)
		if err != nil {
			return nil, err
		}
	}
	privKey, err := crypto.ToECDSA(key.Key)
	if err != nil {
		return nil, err
	}
	return NewAccount(wallet.client, privKey, wallet.logger), nil
}
