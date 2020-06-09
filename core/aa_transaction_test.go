// Copyright 2015 The go-ethereum Authors
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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

const (
	codeWithoutPaygas = "3373ffffffffffffffffffffffffffffffffffffffff1460245736601f57005b600080fd5b00"
	codeWithPaygas    = "3373ffffffffffffffffffffffffffffffffffffffff1460245736601f57005b600080fd5b6001aa00"
)

func aaTransaction(to common.Address, gaslimit uint64) *types.Transaction {
	return types.NewTransaction(0, to, big.NewInt(0), gaslimit, big.NewInt(0), nil).WithAASignature()
}

func setupBlockchain(blockGasLimit uint64) *BlockChain {
	genesis := Genesis{Config: params.AllEthashProtocolChanges, GasLimit: blockGasLimit}
	database := rawdb.NewMemoryDatabase()
	genesis.MustCommit(database)
	blockchain, _ := NewBlockChain(database, nil, genesis.Config, ethash.NewFaker(), vm.Config{}, nil)
	return blockchain
}

func doValidate(blockchain *BlockChain, statedb *state.StateDB, transaction *types.Transaction, validationGasLimit uint64) error {
	var (
		snapshotRevisionId = statedb.Snapshot()
		context            = NewEVMContext(types.AADummyMessage, blockchain.CurrentHeader(), blockchain, &common.Address{})
		vmenv              = vm.NewEVM(context, statedb, blockchain.Config(), vm.Config{})
	)
	defer statedb.RevertToSnapshot(snapshotRevisionId)
	return Validate(transaction, types.HomesteadSigner{}, vmenv, validationGasLimit)
}

func TestAATransactionValidation(t *testing.T) {
	var (
		blockchain = setupBlockchain(10000000)
		statedb, _ = blockchain.State()

		key, _                = crypto.GenerateKey()
		contractCreator       = crypto.PubkeyToAddress(key.PublicKey)
		contractWithoutPaygas = crypto.CreateAddress(contractCreator, 0)
		contractWithPaygas    = crypto.CreateAddress(contractCreator, 1)
	)
	statedb.SetBalance(contractWithoutPaygas, big.NewInt(1000000))
	statedb.SetCode(contractWithoutPaygas, common.FromHex(codeWithoutPaygas))
	statedb.SetBalance(contractWithPaygas, big.NewInt(100000))
	statedb.SetCode(contractWithPaygas, common.FromHex(codeWithPaygas))

	tx := aaTransaction(contractWithoutPaygas, 100000)
	if err := doValidate(blockchain, statedb, tx, 400000); err != ErrNoPaygas {
		t.Error("\n\texpected:", ErrNoPaygas, "\n\tgot:", err)
	}

	tx = aaTransaction(contractWithPaygas, 100000)
	if err := doValidate(blockchain, statedb, tx, 400000); err != nil {
		t.Error("\n\texpected:", "no error", "\n\tgot:", err)
	}

	tx = aaTransaction(contractWithPaygas, 1)
	if err := doValidate(blockchain, statedb, tx, 400000); err != ErrIntrinsicGas {
		t.Error("\n\texpected:", ErrIntrinsicGas, "\n\tgot:", err)
	}

	tx = aaTransaction(contractWithPaygas, 1000000)
	if err := doValidate(blockchain, statedb, tx, 400000); err != vm.ErrPaygasInsufficientFunds {
		t.Error("\n\texpected:", vm.ErrPaygasInsufficientFunds, "\n\tgot:", err)
	}
}
