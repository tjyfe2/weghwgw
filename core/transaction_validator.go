// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)

var (
	ErrIncorrectAAConfig = errors.New("incorrect AA config for EVM")
)

func Validate(tx *types.Transaction, s types.Signer, evm *vm.EVM, gasLimit uint64) error {
	if evm.PaygasMode() != vm.PaygasHalt {
		return ErrIncorrectAAConfig
	}
	evm.SetPaygasLimit(tx.Gas())
	if gasLimit > tx.Gas() {
		gasLimit = tx.Gas()
	}
	msg, err := tx.AsMessage(s)
	msg.SetGas(gasLimit)
	if err != nil {
		return err
	}
	gp := new(GasPool).AddGas(gasLimit)
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return err
	}
	if result.Err != nil {
		return result.Err
	}
	tx.SetAAGasPrice(evm.PaygasPrice())
	return nil
}
