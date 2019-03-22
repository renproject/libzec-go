package libzec_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/libzec-go"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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

	buildHaskLockContract := func(secretHash [32]byte, to btcutil.Address) ([]byte, error) {
		b := txscript.NewScriptBuilder()
		b.AddOp(txscript.OP_SIZE)
		b.AddData([]byte{32})
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_SHA256)
		b.AddData(secretHash[:])
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_DUP)
		b.AddOp(txscript.OP_HASH160)
		b.AddData(to.ScriptAddress())
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_CHECKSIG)
		return b.Script()
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

	getContractDetails := func(spender btcutil.Address, net *chaincfg.Params, secret [32]byte) ([]byte, []byte, btcutil.Address) {
		secretHash := sha256.Sum256(secret[:])
		contract, err := buildHaskLockContract(secretHash, spender)
		if err != nil {
			panic(err)
		}
		hash20 := [20]byte{}
		copy(hash20[:], btcutil.Hash160(contract))
		contractAddress, err := AddressFromHash160(hash20, net, true)
		if err != nil {
			panic(err)
		}
		payToContractPublicKey, err := PayToAddrScript(contractAddress)
		return contract, payToContractPublicKey, contractAddress
	}

	for _, client := range buildClients() {
		var secret [32]byte
		rand.Read(secret[:])

		Context("when interacting with testnet", func() {
			It("should get a valid address of an account", func() {
				mainAccount, _ := getAccounts(client)
				addr, err := mainAccount.Address()
				Expect(err).Should(BeNil())
				Expect(addr.IsForNet(&chaincfg.TestNet3Params)).Should(BeTrue())
				fmt.Println("Address: ", addr)
			})

			It("should get correct network of an account", func() {
				mainAccount, _ := getAccounts(client)
				Expect(mainAccount.NetworkParams()).Should(Equal(&chaincfg.TestNet3Params))
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
				balance, err := mainAccount.Balance(context.Background(), addr.String(), 0)
				Expect(err).Should(BeNil())
				fmt.Printf("%s: %d ZAT", addr, balance)
			})

			It("should transfer 10000 ZAT to another address", func() {
				mainAccount, secondaryAccount := getAccounts(client)
				secAddr, err := secondaryAccount.Address()
				Expect(err).Should(BeNil())
				initialBalance, err := secondaryAccount.Balance(context.Background(), secAddr.String(), 0)
				Expect(err).Should(BeNil())
				// building a transaction to transfer zcash to the secondary address
				_, _, err = mainAccount.Transfer(context.Background(), secAddr.String(), 10000, Fast, false)
				Expect(err).Should(BeNil())
				finalBalance, err := secondaryAccount.Balance(context.Background(), secAddr.String(), 0)
				Expect(err).Should(BeNil())
				Expect(finalBalance - initialBalance).Should(Equal(int64(10000)))
			})

			It("should deposit 50000 ZAT to the contract address", func() {
				mainAccount, secondaryAccount := getAccounts(client)
				spender, err := secondaryAccount.Address()
				Expect(err).Should(BeNil())
				_, payToContractPublicKey, contractAddress := getContractDetails(spender, mainAccount.NetworkParams(), secret)
				initialBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
				Expect(err).Should(BeNil())
				// building a transaction to transfer zcash to the secondary address
				_, _, err = mainAccount.SendTransaction(
					context.Background(),
					nil,
					Fast, // fee
					nil,
					func(msgtx *wire.MsgTx) bool {
						funded, val, err := mainAccount.ScriptFunded(context.Background(), contractAddress.EncodeAddress(), 50000)
						if err != nil {
							fmt.Println(err)
							return false
						}
						if !funded {
							msgtx.AddTxOut(wire.NewTxOut(50000-val, payToContractPublicKey))
						}
						return !funded
					},
					nil,
					func(msgtx *wire.MsgTx) bool {
						funded, _, err := mainAccount.ScriptFunded(context.Background(), contractAddress.EncodeAddress(), 50000)
						if err != nil {
							return false
						}
						return funded
					},
					false,
				)
				Expect(err).Should(BeNil())
				finalBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
				Expect(err).Should(BeNil())
				Expect(finalBalance - initialBalance).Should(Equal(int64(50000)))
			})

			It("should withdraw 50000 ZAT from the contract address", func() {
				_, secondaryAccount := getAccounts(client)
				spender, err := secondaryAccount.Address()
				Expect(err).Should(BeNil())
				contract, _, contractAddress := getContractDetails(spender, secondaryAccount.NetworkParams(), secret)
				initialBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
				Expect(err).Should(BeNil())
				P2PKHScript, err := PayToAddrScript(spender)
				Expect(err).Should(BeNil())

				// building a transaction to transfer zcash to the secondary address
				_, _, err = secondaryAccount.SendTransaction(
					context.Background(),
					contract,
					Fast, // fee
					nil,
					func(msgtx *wire.MsgTx) bool {
						redeemed, val, err := secondaryAccount.ScriptRedeemed(context.Background(), contractAddress.EncodeAddress(), 50000)
						if err != nil {
							return false
						}
						if !redeemed {
							msgtx.AddTxOut(wire.NewTxOut(val, P2PKHScript))
						}
						return !redeemed
					},
					func(builder *txscript.ScriptBuilder) {
						builder.AddData(secret[:])
					},
					func(msgtx *wire.MsgTx) bool {
						fmt.Println("post-con check", contractAddress.EncodeAddress(), spender.EncodeAddress())
						spent, _, err := secondaryAccount.ScriptSpent(context.Background(), contractAddress.EncodeAddress(), spender.EncodeAddress())
						if err != nil {
							return false
						}
						return spent
					},
					true,
				)
				Expect(err).Should(BeNil())
				finalBalance, err := secondaryAccount.Balance(context.Background(), contractAddress.EncodeAddress(), 0)
				Expect(err).Should(BeNil())
				Expect(initialBalance - finalBalance).Should(Equal(int64(50000)))
			})

			It("should be able to extract details from a spent contract", func() {
				mainAccount, secondaryAccount := getAccounts(client)
				spender, err := secondaryAccount.Address()
				Expect(err).Should(BeNil())
				_, _, contractAddress := getContractDetails(spender, mainAccount.NetworkParams(), secret)
				spent, sigScript, err := mainAccount.ScriptSpent(context.Background(), contractAddress.EncodeAddress(), spender.EncodeAddress())
				Expect(err).Should(BeNil())
				Expect(spent).Should(BeTrue())
				Expect(err).Should(BeNil())
				sigScriptBytes, err := hex.DecodeString(sigScript)
				Expect(err).Should(BeNil())
				pushes, err := txscript.PushedData(sigScriptBytes)
				Expect(err).Should(BeNil())
				success := false
				for _, push := range pushes {
					if bytes.Compare(push, secret[:]) == 0 {
						success = true
					}
				}
				Expect(success).Should(BeTrue())
			})
		})
	}
})
