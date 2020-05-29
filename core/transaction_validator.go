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
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)

var (
	ErrIncorrectPaygasMode = errors.New("incorrect PaygasMode for EVM")
)

func Validate(tx *types.Transaction, s types.Signer, evm *vm.EVM) error {
	if evm.PaygasMode() != vm.PaygasHalt {
		return ErrIncorrectPaygasMode
	}
	msg, err := tx.AsMessage(s)
	if err != nil {
		return err
	}
	gp := new(GasPool).AddGas(msg.Gas())
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return err
	}
	if result.Err != nil {
		return result.Err
	}
	price := new(big.Int)
	price.SetBytes(result.ReturnData)
	tx.SetAAGasPrice(price)
	return nil
}
