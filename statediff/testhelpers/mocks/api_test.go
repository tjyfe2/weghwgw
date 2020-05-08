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

package mocks

import (
	"bytes"
	"math/big"
	"sort"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	"github.com/ethereum/go-ethereum/statediff/testhelpers"
)

var (
	emptyStorage                = make([]statediff.StorageDiff, 0)
	emptyAccounts               = make([]statediff.AccountDiff, 0)
	block0, block1              *types.Block
	minerLeafKey                = testhelpers.AddressToLeafKey(common.HexToAddress("0x0"))
	emptyAccountDiffEventualMap = make([]statediff.AccountDiff, 0)
	account1, _                 = rlp.EncodeToBytes(state.Account{
		Nonce:    uint64(0),
		Balance:  big.NewInt(10000),
		CodeHash: common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").Bytes(),
		Root:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	})
	account1LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3926db69aaced518e9b9f0f434a473e7174109c943548bb8f23be41ca76d9ad2"),
		account1,
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
	minerAccount, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    uint64(0),
		Balance:  big.NewInt(2000000000000000000),
		CodeHash: common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").Bytes(),
		Root:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	})
	minerAccountLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"),
		minerAccount,
	})
	bankAccount, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    uint64(1),
		Balance:  big.NewInt(testhelpers.TestBankFunds.Int64() - 10000),
		CodeHash: common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").Bytes(),
		Root:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	})
	bankAccountLeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("30bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2a"),
		bankAccount,
	})
	mockTotalDifficulty = big.NewInt(1337)
)

func TestAPI(t *testing.T) {
	testSubscriptionAPI(t)
	testHTTPAPI(t)
}

func testSubscriptionAPI(t *testing.T) {
	_, blockMap, chain := testhelpers.MakeChain(3, testhelpers.Genesis)
	defer chain.Stop()
	block0Hash := common.HexToHash("0xd1721cfd0b29c36fd7a68f25c128e86413fb666a6e1d68e89b875bd299262661")
	block1Hash := common.HexToHash("0xbbe88de60ba33a3f18c0caa37d827bfb70252e19e40a07cd34041696c35ecb1a")
	block0 = blockMap[block0Hash]
	block1 = blockMap[block1Hash]
	expectedBlockRlp, _ := rlp.EncodeToBytes(block1)
	mockReceipt := &types.Receipt{
		BlockNumber: block1.Number(),
		BlockHash:   block1.Hash(),
	}
	expectedReceiptBytes, _ := rlp.EncodeToBytes(types.Receipts{mockReceipt})
	expectedStateDiff := statediff.StateDiff{
		BlockNumber: block1.Number(),
		BlockHash:   block1.Hash(),
		CreatedAccounts: []statediff.AccountDiff{
			{
				Path:      []byte{'\x05'},
				NodeType:  statediff.Leaf,
				LeafKey:   minerLeafKey,
				NodeValue: minerAccountLeafNode,
				Storage:   emptyStorage,
			},
			{
				Path:      []byte{'\x0e'},
				NodeType:  statediff.Leaf,
				LeafKey:   testhelpers.Account1LeafKey,
				NodeValue: account1LeafNode,
				Storage:   emptyStorage,
			},
			{
				Path:      []byte{'\x00'},
				NodeType:  statediff.Leaf,
				LeafKey:   testhelpers.BankLeafKey,
				NodeValue: bankAccountLeafNode,
				Storage:   emptyStorage,
			},
		},
		DeletedAccounts: []statediff.AccountDiff{ // This leaf appears to be deleted since it is turned into a branch node
			{ // It would instead show up in the UpdateAccounts as new branch node IF intermediate node diffing was turned on (as it is in the test below)
				Path:      []byte{},
				NodeType:  statediff.Leaf,
				LeafKey:   testhelpers.BankLeafKey,
				NodeValue: bankAccountAtBlock0LeafNode,
				Storage:   emptyStorage,
			},
		},
		UpdatedAccounts: emptyAccounts,
	}
	expectedStateDiffBytes, _ := rlp.EncodeToBytes(expectedStateDiff)
	blockChan := make(chan *types.Block)
	parentBlockChain := make(chan *types.Block)
	serviceQuitChan := make(chan bool)
	config := statediff.Config{
		IntermediateNodes: false,
	}
	mockBlockChain := &BlockChain{}
	mockBlockChain.SetReceiptsForHash(block1Hash, types.Receipts{mockReceipt})
	mockBlockChain.SetTdByHash(block1Hash, mockTotalDifficulty)
	mockService := MockStateDiffService{
		Mutex:           sync.Mutex{},
		Builder:         statediff.NewBuilder(chain, config),
		BlockChan:       blockChan,
		BlockChain:      mockBlockChain,
		ParentBlockChan: parentBlockChain,
		QuitChan:        serviceQuitChan,
		Subscriptions:   make(map[rpc.ID]statediff.Subscription),
		streamBlock:     true,
	}
	mockService.Start(nil)
	id := rpc.NewID()
	payloadChan := make(chan statediff.Payload)
	quitChan := make(chan bool)
	mockService.Subscribe(id, payloadChan, quitChan)
	blockChan <- block1
	parentBlockChain <- block0

	sort.Slice(expectedStateDiffBytes, func(i, j int) bool { return expectedStateDiffBytes[i] < expectedStateDiffBytes[j] })
	select {
	case payload := <-payloadChan:
		if !bytes.Equal(payload.BlockRlp, expectedBlockRlp) {
			t.Errorf("payload does not have expected block\r\nactual block rlp: %v\r\nexpected block rlp: %v", payload.BlockRlp, expectedBlockRlp)
		}
		sort.Slice(payload.StateDiffRlp, func(i, j int) bool { return payload.StateDiffRlp[i] < payload.StateDiffRlp[j] })
		if !bytes.Equal(payload.StateDiffRlp, expectedStateDiffBytes) {
			t.Errorf("payload does not have expected state diff\r\nactual state diff rlp: %v\r\nexpected state diff rlp: %v", payload.StateDiffRlp, expectedStateDiffBytes)
		}
		if !bytes.Equal(expectedReceiptBytes, payload.ReceiptsRlp) {
			t.Errorf("payload does not have expected receipts\r\nactual receipt rlp: %v\r\nexpected receipt rlp: %v", payload.ReceiptsRlp, expectedReceiptBytes)
		}
		if !bytes.Equal(payload.TotalDifficulty.Bytes(), mockTotalDifficulty.Bytes()) {
			t.Errorf("payload does not have expected total difficulty\r\nactual td: %d\r\nexpected td: %d", payload.TotalDifficulty.Int64(), mockTotalDifficulty.Int64())
		}
	case <-quitChan:
		t.Errorf("channel quit before delivering payload")
	}
}

func testHTTPAPI(t *testing.T) {
	_, blockMap, chain := testhelpers.MakeChain(3, testhelpers.Genesis)
	defer chain.Stop()
	block0Hash := common.HexToHash("0xd1721cfd0b29c36fd7a68f25c128e86413fb666a6e1d68e89b875bd299262661")
	block1Hash := common.HexToHash("0xbbe88de60ba33a3f18c0caa37d827bfb70252e19e40a07cd34041696c35ecb1a")
	block0 = blockMap[block0Hash]
	block1 = blockMap[block1Hash]
	expectedBlockRlp, _ := rlp.EncodeToBytes(block1)
	mockReceipt := &types.Receipt{
		BlockNumber: block1.Number(),
		BlockHash:   block1.Hash(),
	}
	expectedReceiptBytes, _ := rlp.EncodeToBytes(types.Receipts{mockReceipt})
	expectedStateDiff := statediff.StateDiff{
		BlockNumber: block1.Number(),
		BlockHash:   block1.Hash(),
		CreatedAccounts: []statediff.AccountDiff{
			{
				Path:      []byte{'\x05'},
				NodeType:  statediff.Leaf,
				LeafKey:   minerLeafKey,
				NodeValue: minerAccountLeafNode,
				Storage:   emptyStorage,
			},
			{
				Path:      []byte{'\x0e'},
				NodeType:  statediff.Leaf,
				LeafKey:   testhelpers.Account1LeafKey,
				NodeValue: account1LeafNode,
				Storage:   emptyStorage,
			},
			{
				Path:      []byte{'\x00'},
				NodeType:  statediff.Leaf,
				LeafKey:   testhelpers.BankLeafKey,
				NodeValue: bankAccountLeafNode,
				Storage:   emptyStorage,
			},
		},
		DeletedAccounts: []statediff.AccountDiff{ // This leaf appears to be deleted since it is turned into a branch node
			{ // It would instead show up in the UpdateAccounts as new branch node IF intermediate node diffing was turned on (as it is in the test below)
				Path:      []byte{},
				NodeType:  statediff.Leaf,
				LeafKey:   testhelpers.BankLeafKey,
				NodeValue: bankAccountAtBlock0LeafNode,
				Storage:   emptyStorage,
			},
		},
		UpdatedAccounts: emptyAccounts,
	}
	expectedStateDiffBytes, _ := rlp.EncodeToBytes(expectedStateDiff)
	config := statediff.Config{
		IntermediateNodes: false,
	}
	mockBlockChain := &BlockChain{}
	mockBlockChain.SetBlocksForHashes(blockMap)
	mockBlockChain.SetBlockForNumber(block1, block1.Number().Uint64())
	mockBlockChain.SetReceiptsForHash(block1Hash, types.Receipts{mockReceipt})
	mockBlockChain.SetTdByHash(block1Hash, big.NewInt(1337))
	mockService := MockStateDiffService{
		Mutex:       sync.Mutex{},
		Builder:     statediff.NewBuilder(chain, config),
		BlockChain:  mockBlockChain,
		streamBlock: true,
	}
	payload, err := mockService.StateDiffAt(block1.Number().Uint64())
	if err != nil {
		t.Error(err)
	}
	sort.Slice(payload.StateDiffRlp, func(i, j int) bool { return payload.StateDiffRlp[i] < payload.StateDiffRlp[j] })
	sort.Slice(expectedStateDiffBytes, func(i, j int) bool { return expectedStateDiffBytes[i] < expectedStateDiffBytes[j] })
	if !bytes.Equal(payload.BlockRlp, expectedBlockRlp) {
		t.Errorf("payload does not have expected block\r\nactual block rlp: %v\r\nexpected block rlp: %v", payload.BlockRlp, expectedBlockRlp)
	}
	if !bytes.Equal(payload.StateDiffRlp, expectedStateDiffBytes) {
		t.Errorf("payload does not have expected state diff\r\nactual state diff rlp: %v\r\nexpected state diff rlp: %v", payload.StateDiffRlp, expectedStateDiffBytes)
	}
	if !bytes.Equal(expectedReceiptBytes, payload.ReceiptsRlp) {
		t.Errorf("payload does not have expected receipts\r\nactual receipt rlp: %v\r\nexpected receipt rlp: %v", payload.ReceiptsRlp, expectedReceiptBytes)
	}
	if !bytes.Equal(payload.TotalDifficulty.Bytes(), mockTotalDifficulty.Bytes()) {
		t.Errorf("paylaod does not have the expected total difficulty\r\nactual td: %d\r\nexpected td: %d", payload.TotalDifficulty.Int64(), mockTotalDifficulty.Int64())
	}
}
