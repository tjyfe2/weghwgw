// Copyright 2019 The go-ethereum Authors
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

package statediff_test

import (
	"bytes"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/ethereum/go-ethereum/statediff/testhelpers"
)

var (
	builder         statediff.Builder
	emptyAccountMap = make([]statediff.AccountDiff, 0)
)

type arguments struct {
	oldStateRoot common.Hash
	newStateRoot common.Hash
	blockNumber  *big.Int
	blockHash    common.Hash
}

func loadBlockFromRLPFile(filename string) (*types.Block, []byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	blockRLP, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	block := new(types.Block)
	return block, blockRLP, rlp.DecodeBytes(blockRLP, block)
}

func TestBuilderOnMainnetBlocks(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	gen := core.DefaultGenesisBlock().MustCommit(db)
	genBy, err := rlp.EncodeToBytes(gen)
	if err != nil {
		t.Error(err)
	}
	block0, block0RLP, err := loadBlockFromRLPFile("./block0_rlp")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(genBy, block0RLP) {
		t.Error("mainnet genesis blocks do not match")
	}

	block1, _, err := loadBlockFromRLPFile("./block1_rlp")
	if err != nil {
		t.Error(err)
	}
	block2, _, err := loadBlockFromRLPFile("./block2_rlp")
	if err != nil {
		t.Error(err)
	}
	block3, _, err := loadBlockFromRLPFile("./block3_rlp")
	if err != nil {
		t.Error(err)
	}

	chain, _ := core.NewBlockChain(db, nil, params.MainnetChainConfig, ethash.NewFaker(), vm.Config{}, nil)
	_, err = chain.InsertChain([]*types.Block{block1, block2, block3})
	if err != nil {
		t.Error(err)
	}
	config := statediff.Config{
		IntermediateNodes: true,
	}
	builder = statediff.NewBuilder(chain, config)

	var tests = []struct {
		name              string
		startingArguments arguments
		expected          *statediff.StateDiff
	}{
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			arguments{
				oldStateRoot: testhelpers.NullHash,
				newStateRoot: block0.Root(),
				blockNumber:  block0.Number(),
				blockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber:     block0.Number(),
				BlockHash:       block0.Hash(),
				CreatedAccounts: emptyAccountMap,
				DeletedAccounts: emptyAccountMap,
				UpdatedAccounts: emptyAccountMap,
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			arguments{
				oldStateRoot: block0.Root(),
				newStateRoot: block1.Root(),
				blockNumber:  block1.Number(),
				blockHash:    block1.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber:     block1.Number(),
				BlockHash:       block1.Hash(),
				CreatedAccounts: emptyAccountMap,
				DeletedAccounts: emptyAccountMap,
				UpdatedAccounts: emptyAccountMap,
			},
		},
		{
			"testBlock2",
			// 1000 transferred from testBankAddress to account1Addr
			// 1000 transferred from account1Addr to account2Addr
			// account1addr creates a new contract
			arguments{
				oldStateRoot: block1.Root(),
				newStateRoot: block2.Root(),
				blockNumber:  block2.Number(),
				blockHash:    block2.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber:     block2.Number(),
				BlockHash:       block2.Hash(),
				CreatedAccounts: emptyAccountMap,
				DeletedAccounts: emptyAccountMap,
				UpdatedAccounts: emptyAccountMap,
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			arguments{
				oldStateRoot: block2.Root(),
				newStateRoot: block3.Root(),
				blockNumber:  block3.Number(),
				blockHash:    block3.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber:     block3.Number(),
				BlockHash:       block3.Hash(),
				CreatedAccounts: emptyAccountMap,
				DeletedAccounts: emptyAccountMap,
				UpdatedAccounts: emptyAccountMap,
			},
		},
	}

	for _, test := range tests {
		arguments := test.startingArguments
		diff, err := builder.BuildStateDiff(arguments.oldStateRoot, arguments.newStateRoot, arguments.blockNumber, arguments.blockHash)
		if err != nil {
			t.Error(err)
		}
		receivedStateDiffRlp, err := rlp.EncodeToBytes(diff)
		if err != nil {
			t.Error(err)
		}
		expectedStateDiffRlp, err := rlp.EncodeToBytes(test.expected)
		if err != nil {
			t.Error(err)
		}
		sort.Slice(receivedStateDiffRlp, func(i, j int) bool { return receivedStateDiffRlp[i] < receivedStateDiffRlp[j] })
		sort.Slice(expectedStateDiffRlp, func(i, j int) bool { return expectedStateDiffRlp[i] < expectedStateDiffRlp[j] })
		if !bytes.Equal(receivedStateDiffRlp, expectedStateDiffRlp) {
			t.Logf("Test failed: %s", test.name)
			t.Errorf("actual state diff: %+v\nexpected state diff: %+v", diff, test.expected)
		}
	}
}
