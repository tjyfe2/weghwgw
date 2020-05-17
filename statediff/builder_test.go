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

	balanceChange10000             = int64(10000)
	balanceChange1000              = int64(1000)
	block1BankBalance              = int64(99990000)
	block1Account1Balance          = int64(10000)
	block2Account2Balance          = int64(1000)
	contractContractRoot           = "0x34fbee27a0db0e761bd121ba12d25fcc7bb12ff3fda9a0330e9dcdc91f676aa2"
	newContractRoot                = "0x89fb2012ce3e90bc3ba52a6831ff4722b93f6ea45d0d1311ce4432bd4abd2268"
	ownerAddrStorageLocation       = common.HexToHash("0")
	ownerAddrStorageKey            = crypto.Keccak256Hash(ownerAddrStorageLocation[:])
	originalStorageDataLocation    = common.HexToHash("1")
	originalDataStorageKey         = crypto.Keccak256Hash(originalStorageDataLocation[:])
	newDataStorageLocation         = common.HexToHash("3")
	newStorageKey                  = crypto.Keccak256Hash(newDataStorageLocation[:])
	ownerAddrStorageValue          = common.Hex2Bytes("94703c4b2bd70c169f5717101caee543299fc946c7") // prefixed AccountAddr1
	originalDataStorageValue       = common.Hex2Bytes("01")
	originalDataStorageLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("310e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"),
		originalDataStorageValue,
	})
	ownerAddrStorageLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
		ownerAddrStorageValue,
	})
	newDataStorageValue       = common.Hex2Bytes("03")
	newDataStorageLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("32575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b"),
		newDataStorageValue,
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
		CodeHash: common.HexToHash("0xaaea5efba4fd7b45d7ec03918ac5d8b31aa93b48986af0e6b591f0f087c80127").Bytes(),
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
		CodeHash: common.HexToHash("0xaaea5efba4fd7b45d7ec03918ac5d8b31aa93b48986af0e6b591f0f087c80127").Bytes(),
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
	block2StorageBranchNode, _ = rlp.EncodeToBytes([]interface{}{
		[]byte{},
		[]byte{},
		crypto.Keccak256(ownerAddrStorageLeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(originalDataStorageLeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
	})
	block3StorageBranchNode, _ = rlp.EncodeToBytes([]interface{}{
		[]byte{},
		[]byte{},
		crypto.Keccak256(ownerAddrStorageLeafNode),
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		crypto.Keccak256(originalDataStorageLeafNode),
		crypto.Keccak256(newDataStorageLeafNode),
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
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   ownerAddrStorageKey.Bytes(),
								NodeValue: ownerAddrStorageLeafNode,
							},
							{
								Path:      []byte{'\x0b'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalDataStorageKey.Bytes(),
								NodeValue: originalDataStorageLeafNode,
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
								Path:      []byte{'\x0c'},
								NodeType:  statediff.Leaf,
								LeafKey:   newStorageKey.Bytes(),
								NodeValue: newDataStorageLeafNode,
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
								NodeType:  statediff.Branch,
								NodeValue: block2StorageBranchNode,
							},
							{
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   ownerAddrStorageKey.Bytes(),
								NodeValue: ownerAddrStorageLeafNode,
							},
							{
								Path:      []byte{'\x0b'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalDataStorageKey.Bytes(),
								NodeValue: originalDataStorageLeafNode,
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
								Path:      []byte{'\x0c'},
								NodeType:  statediff.Leaf,
								LeafKey:   newStorageKey.Bytes(),
								NodeValue: newDataStorageLeafNode,
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
								Path:      []byte{'\x02'},
								NodeType:  statediff.Leaf,
								LeafKey:   ownerAddrStorageKey.Bytes(),
								NodeValue: ownerAddrStorageLeafNode,
							},
							{
								Path:      []byte{'\x0b'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalDataStorageKey.Bytes(),
								NodeValue: originalDataStorageLeafNode,
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
								Path:      []byte{'\x0c'},
								NodeType:  statediff.Leaf,
								LeafKey:   newStorageKey.Bytes(),
								NodeValue: newDataStorageLeafNode,
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
		WatchedStorageSlots: []common.Hash{originalDataStorageKey},
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
								Path:      []byte{'\x0b'},
								NodeType:  statediff.Leaf,
								LeafKey:   originalDataStorageKey.Bytes(),
								NodeValue: originalDataStorageLeafNode,
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
						Path:         []byte{'\x06'},
						NodeType:     statediff.Leaf,
						LeafKey:      contractLeafKey,
						NodeValue:    contractAccountAtBlock3LeafNode,
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

/*
func TestBuilderWithMoreAndRemovedStorage(t *testing.T) {
	blocks, chain := testhelpers.MakeChain(5, testhelpers.Genesis)
	contractLeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr)
	emptyContractLeafKey = testhelpers.AddressToLeafKey(testhelpers.EmptyContractAddr)
	defer chain.Stop()
	block4 := blocks[3]
	block5 := blocks[4]
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
		// blocks 0-3 are the same as in TestBuilderWithIntermediateNodes
		{
			"testBlock4",
			statediff.Args{
				OldStateRoot: block3.Root(),
				NewStateRoot: block4.Root(),
				BlockNumber:  block4.Number(),
				BlockHash:    block4.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block4.Number(),
				BlockHash:   block4.Hash(),
				Nodes:       []statediff.StateNode{},
			},
		},
		{
			"testBlock5",
			statediff.Args{
				OldStateRoot: block4.Root(),
				NewStateRoot: block5.Root(),
				BlockNumber:  block5.Number(),
				BlockHash:    block5.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block5.Number(),
				BlockHash:   block5.Hash(),
				Nodes:       []statediff.StateNode{},
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

func TestBuilderWithEIP158RemovedAccount(t *testing.T) {
	blocks, chain := testhelpers.MakeChain(6, testhelpers.Genesis)
	contractLeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr)
	emptyContractLeafKey = testhelpers.AddressToLeafKey(testhelpers.EmptyContractAddr)
	contract2LeafKey = testhelpers.AddressToLeafKey(testhelpers.ContractAddr2)
	defer chain.Stop()
	block5 := blocks[4]
	block6 := blocks[5]
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
		// blocks 0-5 are the same as in TestBuilderWithIntermediateNodes and TestBuilderWithMoreAndRemovedStorage
		{
			"testBlock6",
			statediff.Args{
				OldStateRoot: block5.Root(),
				NewStateRoot: block6.Root(),
				BlockNumber:  block6.Number(),
				BlockHash:    block6.Hash(),
			},
			&statediff.StateDiff{
				BlockNumber: block6.Number(),
				BlockHash:   block6.Hash(),
				Nodes:       []statediff.StateNode{},
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
*/
// Write a test that tests when accounts are deleted, or moved to a new path

/*
pragma solidity ^0.5.10;

contract test {
    address payable owner;

    modifier onlyOwner {
        require(
            msg.sender == owner,
            "Only owner can call this function."
        );
        _;
    }

    uint256[100] data;

	constructor() public {
	    owner = msg.sender;
		data = [1];
	}

    function Put(uint256 addr, uint256 value) public {
        data[addr] = value;
    }

    function close() public onlyOwner { //onlyOwner is custom modifier
        selfdestruct(owner);  // `owner` is the owners address
    }
}
*/
