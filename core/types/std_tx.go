package types

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type StandardTransaction struct{ LegacyTransaction }

func NewStandardTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, gasPrice, data)
}

func NewStrandardContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, gasPrice, data)
}

func newTransaction(nonce uint64, to *common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	i := StandardTransaction{LegacyTransaction{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		GasLimit:     gasLimit,
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}}
	if amount != nil {
		i.Amount.Set(amount)
	}
	if gasPrice != nil {
		i.Price.Set(gasPrice)
	}
	return &Transaction{
		typ:   StandardTxId,
		inner: &i,
		time:  time.Now(),
	}
}
