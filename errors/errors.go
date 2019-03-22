package errors

import (
	"errors"
	"fmt"
)

// ErrPreConditionCheckFailed indicates that the pre-condition for executing
// a transaction failed.
var ErrPreConditionCheckFailed = errors.New("pre-condition check failed")

// ErrPostConditionCheckFailed indicates that the post-condition for executing
// a transaction failed.
var ErrPostConditionCheckFailed = errors.New("post-condition check failed")

var ErrTimedOut = errors.New("timed out")

var ErrNoSpendingTransactions = fmt.Errorf("No spending transactions")

var ErrMismatchedPubKeys = fmt.Errorf("failed to fund the transaction mismatched script public keys")

func NewErrUnsupportedNetwork(network string) error {
	return fmt.Errorf("unsupported network %s", network)
}

func NewErrZCashSubmitTx(msg string) error {
	return fmt.Errorf("error while submitting ZCash transaction: %s", msg)
}
func NewErrInsufficientBalance(address string, required, current int64) error {
	return fmt.Errorf("insufficient balance in %s "+
		"required:%d current:%d", address, required, current)
}
