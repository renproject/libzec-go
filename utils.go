package libzec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/codahale/blake2"
	"github.com/iqoption/zecutil"
)

type upgradeParam struct {
	ActivationHeight uint32
	BranchID         []byte
}

const (
	sigHashMask                = 0x1f
	blake2BSigHash             = "ZcashSigHash"
	outputsHashPersonalization = "ZcashOutputsHash"
)

const (
	versionOverwinter int32 = 3
	versionSapling          = 4
)

const (
	versionOverwinterGroupID uint32 = 0x3C48270
	versionSaplingGroupID           = 0x892f2085
)

var upgradeParams = []upgradeParam{
	{0, []byte{0x00, 0x00, 0x00, 0x00}},
	{207500, []byte{0x19, 0x1B, 0xA8, 0x5B}},
	{280000, []byte{0xBB, 0x09, 0xB8, 0x76}},
}

// blake2bHash zcash hash func
func blake2bHash(data, key []byte) (h chainhash.Hash, err error) {
	bHash := blake2.New(&blake2.Config{
		Size:     32,
		Personal: key,
	})

	if _, err = bHash.Write(data); err != nil {
		return h, err
	}

	err = (&h).SetBytes(bHash.Sum(nil))
	return h, err
}

func CalcSignatureHash(
	subScript []byte,
	hashType txscript.SigHashType,
	tx *zecutil.MsgTx,
	idx int,
	amt int64,
) ([]byte, error) {
	sigHashes, err := zecutil.NewTxSigHashes(tx)
	if err != nil {
		return nil, err
	}

	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.TxIn)-1 {
		return nil, fmt.Errorf("blake2bSignatureHash error: idx %d but %d txins", idx, len(tx.TxIn))
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigHash bytes.Buffer

	// << GetHeader
	// First write out, then encode the transaction's nVersion number. Zcash current nVersion = 3
	var bVersion [4]byte
	binary.LittleEndian.PutUint32(bVersion[:], uint32(tx.Version)|(1<<31))
	sigHash.Write(bVersion[:])

	var versionGroupID = versionOverwinterGroupID
	if tx.Version == versionSapling {
		versionGroupID = versionSaplingGroupID
	}

	// << nVersionGroupId
	// Version group ID
	var nVersion [4]byte
	binary.LittleEndian.PutUint32(nVersion[:], versionGroupID)
	sigHash.Write(nVersion[:])

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash chainhash.Hash

	// << hashPrevouts
	// If anyone can pay isn't active, then we can use the cached
	// hashPrevOuts, otherwise we just write zeroes for the prev outs.
	if hashType&txscript.SigHashAnyOneCanPay == 0 {
		sigHash.Write(sigHashes.HashPrevOuts[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashSequence
	// If the sighash isn't anyone can pay, single, or none, the use the
	// cached hash sequences, otherwise write all zeroes for the
	// hashSequence.
	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashSequence[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashOutputs
	// If the current signature mode isn't single, or none, then we can
	// re-use the pre-generated hashoutputs sighash fragment. Otherwise,
	// we'll serialize and add only the target output index to the signature
	// pre-image.
	if hashType&sigHashMask != txscript.SigHashSingle && hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashOutputs[:])
	} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
		var (
			b bytes.Buffer
			h chainhash.Hash
		)
		if err := wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx]); err != nil {
			return nil, err
		}

		var err error
		if h, err = blake2bHash(b.Bytes(), []byte(outputsHashPersonalization)); err != nil {
			return nil, err
		}
		sigHash.Write(h.CloneBytes())
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashJoinSplits
	sigHash.Write(zeroHash[:])

	// << hashShieldedSpends
	if tx.Version == versionSapling {
		sigHash.Write(zeroHash[:])
	}

	// << hashShieldedOutputs
	if tx.Version == versionSapling {
		sigHash.Write(zeroHash[:])
	}

	// << nLockTime
	var lockTime [4]byte
	binary.LittleEndian.PutUint32(lockTime[:], tx.LockTime)
	sigHash.Write(lockTime[:])

	// << nExpiryHeight
	var expiryTime [4]byte
	binary.LittleEndian.PutUint32(expiryTime[:], tx.ExpiryHeight)
	sigHash.Write(expiryTime[:])

	// << valueBalance
	if tx.Version == versionSapling {
		var valueBalance [8]byte
		binary.LittleEndian.PutUint64(valueBalance[:], 0)
		sigHash.Write(valueBalance[:])
	}

	// << nHashType
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType))
	sigHash.Write(bHashType[:])

	if idx != math.MaxUint32 {
		// << prevout
		// Next, write the outpoint being spent.
		sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
		var bIndex [4]byte
		binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
		sigHash.Write(bIndex[:])

		// << scriptCode
		// For p2wsh outputs, and future outputs, the script code is the
		// original script, with all code separators removed, serialized
		// with a var int length prefix.
		// wire.WriteVarBytes(&sigHash, 0, subScript)
		if err := wire.WriteVarBytes(&sigHash, 0, subScript); err != nil {
			return nil, err
		}

		// << amount
		// Next, add the input amount, and sequence number of the input being
		// signed.
		if err := binary.Write(&sigHash, binary.LittleEndian, amt); err != nil {
			return nil, err
		}

		// << nSequence
		var bSequence [4]byte
		binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
		sigHash.Write(bSequence[:])
	}

	var h chainhash.Hash
	if h, err = blake2bHash(sigHash.Bytes(), sigHashKey(tx.ExpiryHeight)); err != nil {
		return nil, err
	}

	return h.CloneBytes(), nil
}

// sigHashKey return blake2b key by current height
func sigHashKey(activationHeight uint32) []byte {
	var i int
	for i = len(upgradeParams) - 1; i >= 0; i-- {
		if activationHeight >= upgradeParams[i].ActivationHeight {
			break
		}
	}

	return append([]byte(blake2BSigHash), upgradeParams[i].BranchID...)
}
