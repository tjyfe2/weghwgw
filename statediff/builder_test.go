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
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/ethereum/go-ethereum/statediff/testhelpers"
)

// TODO: add test that filters on address
var (
	contractLeafKey                []byte
	emptyDiffs                     = make([]statediff.StateNode, 0)
	emptyStorage                   = make([]statediff.StorageNode, 0)
	block0, block1, block2, block3 *types.Block
	builder                        statediff.Builder
	miningReward                   = int64(2000000000000000000)
	minerAddress                   = common.HexToAddress("0x0")
	minerLeafKey                   = testhelpers.AddressToLeafKey(minerAddress)

	balanceChange10000         = int64(10000)
	balanceChange1000          = int64(1000)
	block1BankBalance          = int64(99990000)
	block1Account1Balance      = int64(10000)
	block2Account2Balance      = int64(1000)
	contractContractRoot       = "0x821e2556a290c86405f8160a2d662042a431ba456b9db265c79bb837c04be5f0"
	newContractRoot            = "0x71e0d14b2b93e5c7f9748e69e1fe5f17498a1c3ac3cec29f96af13d7f8a4e070"
	originalStorageLocation    = common.HexToHash("0")
	originalStorageKey         = crypto.Keccak256Hash(originalStorageLocation[:])
	newStorageLocation         = common.HexToHash("2")
	newStorageKey              = crypto.Keccak256Hash(newStorageLocation[:])
	originalStorageValue       = common.Hex2Bytes("01")
	originalStorageLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("20290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
		originalStorageValue,
	})
	updatedStorageLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
		originalStorageValue,
	})
	newStorageValue       = common.Hex2Bytes("03")
	newStorageLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("305787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"),
		newStorageValue,
	})
	bankAccountAtBlock0, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce0,
		Balance:  big.NewInt(testhelpers.TestBankFunds.Int64()),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	bankAccountAtBlock0LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("2000bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2a"),
		bankAccountAtBlock0,
	})
	account1AtBlock1, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce0,
		Balance:  big.NewInt(balanceChange10000),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	account1AtBlock1LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3926db69aaced518e9b9f0f434a473e7174109c943548bb8f23be41ca76d9ad2"),
		account1AtBlock1,
	})
	minerAccountAtBlock1, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce0,
		Balance:  big.NewInt(miningReward),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	minerAccountAtBlock1LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"),
		minerAccountAtBlock1,
	})
	bankAccountAtBlock1, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce1,
		Balance:  big.NewInt(testhelpers.TestBankFunds.Int64() - balanceChange10000),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	bankAccountAtBlock1LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("30bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2a"),
		bankAccountAtBlock1,
	})
	account2AtBlock2, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce0,
		Balance:  big.NewInt(balanceChange1000),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	account2AtBlock2LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3957f3e2f04a0764c3a0491b175f69926da61efbcc8f61fa1455fd2d2b4cdd45"),
		account2AtBlock2,
	})
	contractAccountAtBlock2, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce1,
		Balance:  big.NewInt(0),
		CodeHash: common.HexToHash("0x753f98a8d4328b15636e46f66f2cb4bc860100aa17967cc145fcd17d1d4710ea").Bytes(),
		Root:     common.HexToHash(contractContractRoot),
	})
	contractAccountAtBlock2LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3114658a74d9cc9f7acf2c5cd696c3494d7c344d78bfec3add0d91ec4e8d1c45"),
		contractAccountAtBlock2,
	})
	bankAccountAtBlock2, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce2,
		Balance:  big.NewInt(block1BankBalance - balanceChange1000),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	bankAccountAtBlock2LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("30bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2a"),
		bankAccountAtBlock2,
	})
	account1AtBlock2, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce2,
		Balance:  big.NewInt(block1Account1Balance - balanceChange1000 + balanceChange1000),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	account1AtBlock2LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3926db69aaced518e9b9f0f434a473e7174109c943548bb8f23be41ca76d9ad2"),
		account1AtBlock2,
	})
	minerAccountAtBlock2, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce0,
		Balance:  big.NewInt(miningReward + miningReward),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	minerAccountAtBlock2LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"),
		minerAccountAtBlock2,
	})
	account2AtBlock3, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce0,
		Balance:  big.NewInt(block2Account2Balance + miningReward),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	account2AtBlock3LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3957f3e2f04a0764c3a0491b175f69926da61efbcc8f61fa1455fd2d2b4cdd45"),
		account2AtBlock3,
	})
	contractAccountAtBlock3, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce1,
		Balance:  big.NewInt(0),
		CodeHash: common.HexToHash("0x753f98a8d4328b15636e46f66f2cb4bc860100aa17967cc145fcd17d1d4710ea").Bytes(),
		Root:     common.HexToHash(newContractRoot),
	})
	contractAccountAtBlock3LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3114658a74d9cc9f7acf2c5cd696c3494d7c344d78bfec3add0d91ec4e8d1c45"),
		contractAccountAtBlock3,
	})
	bankAccountAtBlock3, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    testhelpers.Nonce3,
		Balance:  big.NewInt(99989000),
		CodeHash: testhelpers.NullCodeHash.Bytes(),
		Root:     testhelpers.EmptyContractRoot,
	})
	bankAccountAtBlock3LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("30bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2a"),
		bankAccountAtBlock3,
	})

	block1BranchNode, _ = rlp.EncodeToBytes([]interface{}{
		crypto.Keccak256(bankAccountAtBlock1LeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(minerAccountAtBlock1LeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(account1AtBlock1LeafNode),
		[]byte{},
		[]byte{},
	})
	block2BranchNode, _ = rlp.EncodeToBytes([]interface{}{
		crypto.Keccak256(bankAccountAtBlock2LeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(minerAccountAtBlock2LeafNode),
		crypto.Keccak256(contractAccountAtBlock2LeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(account2AtBlock2LeafNode),
		[]byte{},
		crypto.Keccak256(account1AtBlock2LeafNode),
		[]byte{},
		[]byte{},
	})
	block3BranchNode, _ = rlp.EncodeToBytes([]interface{}{
		crypto.Keccak256(bankAccountAtBlock3LeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(minerAccountAtBlock2LeafNode),
		crypto.Keccak256(contractAccountAtBlock3LeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(account2AtBlock3LeafNode),
		[]byte{},
		crypto.Keccak256(account1AtBlock2LeafNode),
		[]byte{},
		[]byte{},
	})
	block3StorageBranchNode, _ = rlp.EncodeToBytes([]interface{}{
		[]byte{},
		[]byte{},
		crypto.Keccak256(updatedStorageLeafNode),
		[]byte{},
		crypto.Keccak256(newStorageLeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
	})
)

func TestBuilder(t *testing.T) {
	blocks, chain := testhelpers.MakeChain(3, testhelpers.Genesis)
	contractLeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr)
	defer chain.Stop()
	block0 = testhelpers.Genesis
	block1 = blocks[0]
	block2 = blocks[1]
	block3 = blocks[2]
	params := statediff.Params{}
	builder = statediff.NewBuilder(chain.StateCache())

	var tests = []struct {
		name              string
		startingArguments statediff.Args
		expected          *statediff.StateDiff
	}{
		{
			"testEmptyDiff",
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes:       emptyDiffs,
			},
		},
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: testhelpers.NullHash,
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock0LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block1.Root(),
				BlockNumber:  block1.Number(),
				BlockHash:    block1.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block1.Number(),
				BlockHash:   block1.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{'\x00'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x05'},
						NodeType:     statediff.Leaf,
						LeafKey:      minerLeafKey,
						NodeValue:    minerAccountAtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock2",
			// 1000 transferred from testBankAddress to account1Addr
			// 1000 transferred from account1Addr to account2Addr
			// account1addr creates a new contract
			statediff.Args{
				OldStateRoot: block1.Root(),
				NewStateRoot: block2.Root(),
				BlockNumber:  block2.Number(),
				BlockHash:    block2.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block2.Number(),
				BlockHash:   block2.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{'\x00'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x05'},
						NodeType:     statediff.Leaf,
						LeafKey:      minerLeafKey,
						NodeValue:    minerAccountAtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock2LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: originalStorageLeafNode,
							},
						},
					},
					{
						Path:         []byte{'\x0c'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account2LeafKey,
						NodeValue:    account2AtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			statediff.Args{
				OldStateRoot: block2.Root(),
				NewStateRoot: block3.Root(),
				BlockNumber:  block3.Number(),
				BlockHash:    block3.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block3.Number(),
				BlockHash:   block3.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{'\x00'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock3LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock3LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: updatedStorageLeafNode,
							},
							{
								Path:      []byte{'\x04'},
								NodeType:  statediff.Leaf,
								LeafKey:   newStorageKey.Bytes(),
								NodeValue: newStorageLeafNode,
							},
						},
					},
					{
						Path:         []byte{'\x0c'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account2LeafKey,
						NodeValue:    account2AtBlock3LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
	}

	for _, test := range tests {
		diff, err := builder.BuildStateDiff(test.startingArguments, params)
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

func TestBuilderWithIntermediateNodes(t *testing.T) {
	blocks, chain := testhelpers.MakeChain(3, testhelpers.Genesis)
	contractLeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr)
	defer chain.Stop()
	block0 = testhelpers.Genesis
	block1 = blocks[0]
	block2 = blocks[1]
	block3 = blocks[2]
	params := statediff.Params{
		IntermediateStateNodes:   true,
		IntermediateStorageNodes: true,
	}
	builder = statediff.NewBuilder(chain.StateCache())

	var tests = []struct {
		name              string
		startingArguments statediff.Args
		expected          *statediff.StateDiff
	}{
		{
			"testEmptyDiff",
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes:       emptyDiffs,
			},
		},
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: testhelpers.NullHash,
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock0LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block1.Root(),
				BlockNumber:  block1.Number(),
				BlockHash:    block1.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block1.Number(),
				BlockHash:   block1.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{},
						NodeType:     statediff.Branch,
						NodeValue:    block1BranchNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x00'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x05'},
						NodeType:     statediff.Leaf,
						LeafKey:      minerLeafKey,
						NodeValue:    minerAccountAtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock2",
			// 1000 transferred from testBankAddress to account1Addr
			// 1000 transferred from account1Addr to account2Addr
			// account1addr creates a new contract
			statediff.Args{
				OldStateRoot: block1.Root(),
				NewStateRoot: block2.Root(),
				BlockNumber:  block2.Number(),
				BlockHash:    block2.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block2.Number(),
				BlockHash:   block2.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{},
						NodeType:     statediff.Branch,
						NodeValue:    block2BranchNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x00'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x05'},
						NodeType:     statediff.Leaf,
						LeafKey:      minerLeafKey,
						NodeValue:    minerAccountAtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock2LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: originalStorageLeafNode,
							},
						},
					},
					{
						Path:         []byte{'\x0c'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account2LeafKey,
						NodeValue:    account2AtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			statediff.Args{
				OldStateRoot: block2.Root(),
				NewStateRoot: block3.Root(),
				BlockNumber:  block3.Number(),
				BlockHash:    block3.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block3.Number(),
				BlockHash:   block3.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{},
						NodeType:     statediff.Branch,
						NodeValue:    block3BranchNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:         []byte{'\x00'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.BankLeafKey,
						NodeValue:    bankAccountAtBlock3LeafNode,
						StorageDiffs: emptyStorage,
					},
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock3LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{},
								NodeType:  statediff.Branch,
								NodeValue: block3StorageBranchNode,
							},
							{
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: updatedStorageLeafNode,
							},
							{
								Path:      []byte{'\x04'},
								NodeType:  statediff.Leaf,
								LeafKey:   newStorageKey.Bytes(),
								NodeValue: newStorageLeafNode,
							},
						},
					},
					{
						Path:         []byte{'\x0c'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account2LeafKey,
						NodeValue:    account2AtBlock3LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
	}

	for _, test := range tests {
		diff, err := builder.BuildStateDiff(test.startingArguments, params)
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
			t.Errorf("actual state diff: %+v\r\n\r\n\r\nexpected state diff: %+v", diff, test.expected)
		}
	}
}

func TestBuilderWithWatchedAddressList(t *testing.T) {
	blocks, chain := testhelpers.MakeChain(3, testhelpers.Genesis)
	contractLeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr)
	defer chain.Stop()
	block0 = testhelpers.Genesis
	block1 = blocks[0]
	block2 = blocks[1]
	block3 = blocks[2]
	params := statediff.Params{
		WatchedAddresses: []common.Address{testhelpers.Account1Addr, testhelpers.ContractAddr},
	}
	builder = statediff.NewBuilder(chain.StateCache())

	var tests = []struct {
		name              string
		startingArguments statediff.Args
		expected          *statediff.StateDiff
	}{
		{
			"testEmptyDiff",
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes:       emptyDiffs,
			},
		},
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: testhelpers.NullHash,
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes:       emptyDiffs,
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block1.Root(),
				BlockNumber:  block1.Number(),
				BlockHash:    block1.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block1.Number(),
				BlockHash:   block1.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock2",
			//1000 transferred from testBankAddress to account1Addr
			//1000 transferred from account1Addr to account2Addr
			statediff.Args{
				OldStateRoot: block1.Root(),
				NewStateRoot: block2.Root(),
				BlockNumber:  block2.Number(),
				BlockHash:    block2.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block2.Number(),
				BlockHash:   block2.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock2LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: originalStorageLeafNode,
							},
						},
					},
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			statediff.Args{
				OldStateRoot: block2.Root(),
				NewStateRoot: block3.Root(),
				BlockNumber:  block3.Number(),
				BlockHash:    block3.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block3.Number(),
				BlockHash:   block3.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock3LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: updatedStorageLeafNode,
							},
							{
								Path:      []byte{'\x04'},
								NodeType:  statediff.Leaf,
								LeafKey:   newStorageKey.Bytes(),
								NodeValue: newStorageLeafNode,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		diff, err := builder.BuildStateDiff(test.startingArguments, params)
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

func TestBuilderWithWatchedAddressAndStorageKeyList(t *testing.T) {
	blocks, chain := testhelpers.MakeChain(3, testhelpers.Genesis)
	contractLeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr)
	defer chain.Stop()
	block0 = testhelpers.Genesis
	block1 = blocks[0]
	block2 = blocks[1]
	block3 = blocks[2]
	params := statediff.Params{
		WatchedAddresses:    []common.Address{testhelpers.Account1Addr, testhelpers.ContractAddr},
		WatchedStorageSlots: []common.Hash{originalStorageKey},
	}
	builder = statediff.NewBuilder(chain.StateCache())

	var tests = []struct {
		name              string
		startingArguments statediff.Args
		expected          *statediff.StateDiff
	}{
		{
			"testEmptyDiff",
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes:       emptyDiffs,
			},
		},
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: testhelpers.NullHash,
				NewStateRoot: block0.Root(),
				BlockNumber:  block0.Number(),
				BlockHash:    block0.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block0.Number(),
				BlockHash:   block0.Hash(),
				Nodes:       emptyDiffs,
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			statediff.Args{
				OldStateRoot: block0.Root(),
				NewStateRoot: block1.Root(),
				BlockNumber:  block1.Number(),
				BlockHash:    block1.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block1.Number(),
				BlockHash:   block1.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock1LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock2",
			//1000 transferred from testBankAddress to account1Addr
			//1000 transferred from account1Addr to account2Addr
			statediff.Args{
				OldStateRoot: block1.Root(),
				NewStateRoot: block2.Root(),
				BlockNumber:  block2.Number(),
				BlockHash:    block2.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block2.Number(),
				BlockHash:   block2.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock2LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: originalStorageLeafNode,
							},
						},
					},
					{
						Path:         []byte{'\x0e'},
						NodeType:     statediff.Leaf,
						LeafKey:      testhelpers.Account1LeafKey,
						NodeValue:    account1AtBlock2LeafNode,
						StorageDiffs: emptyStorage,
					},
				},
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			statediff.Args{
				OldStateRoot: block2.Root(),
				NewStateRoot: block3.Root(),
				BlockNumber:  block3.Number(),
				BlockHash:    block3.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block3.Number(),
				BlockHash:   block3.Hash(),
				Nodes: []statediff.StateNode{
					{
						Path:      []byte{'\x06'},
						NodeType:  statediff.Leaf,
						LeafKey:   contractLeafKey,
						NodeValue: contractAccountAtBlock3LeafNode,
						StorageDiffs: []statediff.StorageNode{
							{
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalStorageKey.Bytes(),
								NodeValue: updatedStorageLeafNode,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		diff, err := builder.BuildStateDiff(test.startingArguments, params)
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

// Write a test that tests when accounts are deleted, or moved to a new path

/*
contract test {

    uint256[100] data;

	constructor() public {
		data = [1];
	}

    function Put(uint256 addr, uint256 value) {
        data[addr] = value;
    }

    function Get(uint256 addr) constant returns (uint256 value) {
        return data[addr];
    }
}
*/
