package libzec_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/libzec-go"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip39"
)

var _ = Describe("LibZEC", func() {
	loadMasterKey := func(network uint32) (*hdkeychain.ExtendedKey, error) {
		switch network {
		case 1:
			seed := bip39.NewSeed(os.Getenv("TESTNET_MNEMONIC"), os.Getenv("TESTNET_PASSPHRASE"))
			return hdkeychain.NewMaster(seed, &chaincfg.TestNet3Params)
		case 0:
			seed := bip39.NewSeed(os.Getenv("MNEMONIC"), os.Getenv("PASSPHRASE"))
			return hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
		default:
			return nil, NewErrUnsupportedNetwork(fmt.Sprintf("network id: %d", network))
		}
	}

	loadKey := func(path ...uint32) (*ecdsa.PrivateKey, error) {
		key, err := loadMasterKey(path[1])
		if err != nil {
			return nil, err
		}
		for _, val := range path {
			key, err = key.Child(val)
			if err != nil {
				return nil, err
			}
		}
		privKey, err := key.ECPrivKey()
		if err != nil {
			return nil, err
		}
		return privKey.ToECDSA(), nil
	}

	buildClients := func() []Client {
		APIClient, err := NewMercuryClient("testnet")
		if err != nil {
			panic(err)
		}
		return []Client{APIClient}
	}

	getAccounts := func(client Client) (Account, Account) {
		mainKey, err := loadKey(44, 1, 0, 0, 0) // "m/44'/1'/0'/0/0"
		if err != nil {
			panic(err)
		}
		mainAccount := NewAccount(client, mainKey, logrus.StandardLogger())
		secKey, err := loadKey(44, 1, 1, 0, 0) // "m/44'/1'/1'/0/0"
		if err != nil {
			panic(err)
		}
		secondaryAccount := NewAccount(client, secKey, logrus.StandardLogger())
		return mainAccount, secondaryAccount
	}

	Context("when interacting with mainnet", func() {
		It("should get a valid address of an account", func() {
			client, err := NewMercuryClient("mainnet")
			Expect(err).Should(BeNil())
			mainAccount, _ := getAccounts(client)
			addr, err := mainAccount.Address()
			Expect(err).Should(BeNil())
			Expect(addr.IsForNet(&chaincfg.MainNetParams)).Should(BeTrue())
		})

		It("should get correct network of an account", func() {
			client, err := NewMercuryClient("mainnet")
			Expect(err).Should(BeNil())
			mainAccount, _ := getAccounts(client)
			Expect(mainAccount.NetworkParams()).Should(Equal(&chaincfg.MainNetParams))
		})

		It("should get a valid serialized public key of an account", func() {
			client, err := NewMercuryClient("mainnet")
			Expect(err).Should(BeNil())
			mainAccount, _ := getAccounts(client)
			pubKey, err := mainAccount.SerializedPublicKey()
			Expect(err).Should(BeNil())
			Expect(btcec.IsCompressedPubKey(pubKey)).Should(BeTrue())
			_, err = btcec.ParsePubKey(pubKey, btcec.S256())
			Expect(err).Should(BeNil())
		})

		It("should get the balance of an address", func() {
			client, err := NewMercuryClient("mainnet")
			Expect(err).Should(BeNil())
			mainAccount, _ := getAccounts(client)
			addr, err := mainAccount.Address()
			Expect(err).Should(BeNil())
			_, err = mainAccount.Balance(addr.String(), 0)
			Expect(err).Should(BeNil())
		})
	})

	for _, client := range buildClients() {
		var secret [32]byte
		rand.Read(secret[:])

		Context("when interacting with testnet", func() {
			It("should get a valid address of an account", func() {
				mainAccount, _ := getAccounts(client)
				addr, err := mainAccount.Address()
				Expect(err).Should(BeNil())
				Expect(addr.IsForNet(&chaincfg.TestNet3Params)).Should(BeTrue())
			})

			It("should get correct network of an account", func() {
				mainAccount, _ := getAccounts(client)
				Expect(mainAccount.NetworkParams()).Should(Equal(&chaincfg.TestNet3Params))
			})

			It("should get a utxo", func() {
				mainAccount, _ := getAccounts(client)
				addr, err := mainAccount.Address()
				Expect(err).Should(BeNil())
				utxos, err := mainAccount.GetUTXOs(addr.EncodeAddress(), 1, 0)
				Expect(err).Should(BeNil())
				actualUTXO := utxos[0]
				fmt.Println(actualUTXO.TxHash, actualUTXO.Vout)
				utxo, err := mainAccount.GetUTXO(actualUTXO.TxHash, actualUTXO.Vout)
				Expect(err).Should(BeNil())
				Expect(reflect.DeepEqual(actualUTXO, utxo)).Should(BeTrue())
			})

			It("should get a valid serialized public key of an account", func() {
				mainAccount, _ := getAccounts(client)
				pubKey, err := mainAccount.SerializedPublicKey()
				Expect(err).Should(BeNil())
				Expect(btcec.IsCompressedPubKey(pubKey)).Should(BeFalse())
				_, err = btcec.ParsePubKey(pubKey, btcec.S256())
				Expect(err).Should(BeNil())
			})

			It("should get the balance of an address", func() {
				mainAccount, _ := getAccounts(client)
				addr, err := mainAccount.Address()
				Expect(err).Should(BeNil())
				_, err = mainAccount.Balance(addr.String(), 0)
				Expect(err).Should(BeNil())
			})

			It("should transfer 5000000 ZAT to another address", func() {
				mainAccount, secondaryAccount := getAccounts(client)
				secAddr, err := secondaryAccount.Address()
				Expect(err).Should(BeNil())
				initialBalance, err := secondaryAccount.Balance(secAddr.EncodeAddress(), 0)
				Expect(err).Should(BeNil())
				// building a transaction to transfer zcash to the secondary address
				_, _, err = mainAccount.Transfer(context.Background(), secAddr.EncodeAddress(), 5010000, Fast, false)
				Expect(err).Should(BeNil())
				finalBalance, err := secondaryAccount.Balance(secAddr.EncodeAddress(), 0)
				Expect(err).Should(BeNil())
				Expect(finalBalance - initialBalance).Should(Equal(int64(5000000)))
			})

			It("should transfer 10000 ZAT to another address", func() {
				mainKey, err := loadKey(44, 1, 0, 0, 0) // "m/44'/1'/0'/0/0"
				Expect(err).Should(BeNil())
				mainPrivKey := (*btcec.PrivateKey)(mainKey)

				mainAccount, secondaryAccount := getAccounts(client)
				mainAddr, err := mainAccount.Address()
				Expect(err).Should(BeNil())
				secAddr, err := secondaryAccount.Address()
				Expect(err).Should(BeNil())
				utxos, err := client.GetUTXOs(mainAddr.String(), 10, 0)
				Expect(err).Should(BeNil())
				builder := NewTxBuilder(client)
				tx, err := builder.Build(mainKey.PublicKey, secAddr.String(), nil, 20000, utxos, nil)
				Expect(err).Should(BeNil())

				hashes := tx.Hashes()
				sigs := make([]*btcec.Signature, len(hashes))
				for i, hash := range hashes {
					sigs[i], err = mainPrivKey.Sign(hash)
					Expect(err).Should(BeNil())
				}
				Expect(tx.InjectSigs(sigs)).Should(BeNil())

				initialBalance, err := secondaryAccount.Balance(secAddr.String(), 0)
				Expect(err).Should(BeNil())
				// building a transaction to transfer zcash to the secondary address
				txHash, err := tx.Submit()
				Expect(err).Should(BeNil())
				fmt.Printf(mainAccount.FormatTransactionView("successfully submitted transfer tx", hex.EncodeToString(txHash)))
				finalBalance, err := secondaryAccount.Balance(secAddr.String(), 0)
				Expect(err).Should(BeNil())
				Expect(finalBalance - initialBalance).Should(Equal(int64(10000)))
			})

			It("should transfer 10000 ZAT from a slave address", func() {
				mainKey, err := loadKey(44, 1, 0, 0, 0) // "m/44'/1'/0'/0/0"
				Expect(err).Should(BeNil())
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				mainPrivKey := (*btcec.PrivateKey)(mainKey)

				mainAccount, secondaryAccount := getAccounts(client)
				nonce := [32]byte{}
				rand.Read(nonce[:])
				pubKeyBytes, err := client.SerializePublicKey((*btcec.PublicKey)(&mainPrivKey.PublicKey))
				Expect(err).Should(BeNil())
				slaveAddr, err := mainAccount.SlaveAddress(btcutil.Hash160(pubKeyBytes), nonce[:])
				Expect(err).Should(BeNil())
				slaveScript, err := mainAccount.SlaveScript(btcutil.Hash160(pubKeyBytes), nonce[:])
				Expect(err).Should(BeNil())
				_, _, err = mainAccount.Transfer(ctx, slaveAddr.String(), 30000, Fast, false)
				Expect(err).Should(BeNil())

				mainAddr, err := mainAccount.Address()
				Expect(err).Should(BeNil())
				mwUTXOs, err := client.GetUTXOs(mainAddr.String(), 10, 0)
				Expect(err).Should(BeNil())
				scriptUTXOs, err := client.GetUTXOs(slaveAddr.String(), 10, 0)
				Expect(err).Should(BeNil())
				builder := NewTxBuilder(client)
				tx, err := builder.Build(mainKey.PublicKey, mainAddr.String(), slaveScript, 20000, mwUTXOs, scriptUTXOs)
				Expect(err).Should(BeNil())

				hashes := tx.Hashes()
				sigs := make([]*btcec.Signature, len(hashes))
				for i, hash := range hashes {
					sigs[i], err = mainPrivKey.Sign(hash)
					Expect(err).Should(BeNil())
				}
				Expect(tx.InjectSigs(sigs)).Should(BeNil())
				initialBalance, err := secondaryAccount.Balance(mainAddr.String(), 0)
				Expect(err).Should(BeNil())
				// building a transaction to receive bitcoin from a script address
				txHash, err := tx.Submit()
				Expect(err).Should(BeNil())
				fmt.Printf(mainAccount.FormatTransactionView("successfully submitted transfer tx", hex.EncodeToString(txHash)))
				finalBalance, err := secondaryAccount.Balance(mainAddr.String(), 0)
				Expect(err).Should(BeNil())
				Expect(finalBalance - initialBalance).Should(Equal(int64(10000)))
			})
		})
	}
})
