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
	block0, block1              *types.Block
	burnLeafKey                 = testhelpers.AddressToEncodedPath(common.HexToAddress("0x0"))
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
	burnAccount1, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    uint64(0),
		Balance:  big.NewInt(2000000000000000000),
		CodeHash: common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").Bytes(),
		Root:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	})
	burnAccount1LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("3380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"),
		burnAccount1,
	})
	bankAccount1, _ = rlp.EncodeToBytes(state.Account{
		Nonce:    uint64(1),
		Balance:  big.NewInt(testhelpers.TestBankFunds.Int64() - 10000),
		CodeHash: common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").Bytes(),
		Root:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	})
	bankAccount1LeafNode, _ = rlp.EncodeToBytes([]interface{}{
		common.Hex2Bytes("30bf49f440a1cd0527e4d06e2765654c0f56452257516d793a9b8d604dcfdf2a"),
		bankAccount1,
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
				NodeType:    statediff.Leaf,
				EncodedPath: burnLeafKey,
				NodeValue:   burnAccount1LeafNode,
				Proof: [][]byte{{248, 113, 160, 87, 118, 82, 182, 37, 183, 123, 219, 91, 247, 123, 196, 63, 49, 37, 202, 215, 70, 77, 103, 157, 21, 117, 86, 82, 119, 211, 97, 27, 128, 83, 231, 128, 128, 128, 128, 160, 254, 136, 159, 16, 229, 219, 143, 44, 43, 243, 85, 146, 129, 82, 161, 127, 110, 59, 185, 154, 146, 65, 172, 109, 132, 199, 126, 98, 100, 80, 156, 121, 128, 128, 128, 128, 128, 128, 128, 128, 160, 17, 219, 12, 218, 52, 168, 150, 218, 190, 182, 131, 155, 176, 106, 56, 244, 149, 20, 207, 164, 134, 67, 89, 132, 235, 1, 59, 125, 249, 238, 133, 197, 128, 128},
					{248, 113, 160, 51, 128, 199, 183, 174, 129, 165, 142, 185, 141, 156, 120, 222, 74, 31, 215, 253, 149, 53, 252, 149, 62, 210, 190, 96, 45, 170, 164, 23, 103, 49, 42, 184, 78, 248, 76, 128, 136, 27, 193, 109, 103, 78, 200, 0, 0, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
				Storage: []statediff.StorageDiff{},
			},
			{
				NodeType:    statediff.Leaf,
				EncodedPath: testhelpers.Account1LeafKey,
				NodeValue:   account1LeafNode,
				Proof: [][]byte{{248, 113, 160, 87, 118, 82, 182, 37, 183, 123, 219, 91, 247, 123, 196, 63, 49, 37, 202, 215, 70, 77, 103, 157, 21, 117, 86, 82, 119, 211, 97, 27, 128, 83, 231, 128, 128, 128, 128, 160, 254, 136, 159, 16, 229, 219, 143, 44, 43, 243, 85, 146, 129, 82, 161, 127, 110, 59, 185, 154, 146, 65, 172, 109, 132, 199, 126, 98, 100, 80, 156, 121, 128, 128, 128, 128, 128, 128, 128, 128, 160, 17, 219, 12, 218, 52, 168, 150, 218, 190, 182, 131, 155, 176, 106, 56, 244, 149, 20, 207, 164, 134, 67, 89, 132, 235, 1, 59, 125, 249, 238, 133, 197, 128, 128},
					{248, 107, 160, 57, 38, 219, 105, 170, 206, 213, 24, 233, 185, 240, 244, 52, 164, 115, 231, 23, 65, 9, 201, 67, 84, 139, 184, 242, 59, 228, 28, 167, 109, 154, 210, 184, 72, 248, 70, 128, 130, 39, 16, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
				Storage: []statediff.StorageDiff{},
			},
		},
		DeletedAccounts: emptyAccountDiffEventualMap,
		UpdatedAccounts: []statediff.AccountDiff{
			{
				NodeType:    statediff.Leaf,
				EncodedPath: testhelpers.BankLeafKey,
				NodeValue:   bankAccount1LeafNode,
				Proof: [][]byte{{248, 113, 160, 87, 118, 82, 182, 37, 183, 123, 219, 91, 247, 123, 196, 63, 49, 37, 202, 215, 70, 77, 103, 157, 21, 117, 86, 82, 119, 211, 97, 27, 128, 83, 231, 128, 128, 128, 128, 160, 254, 136, 159, 16, 229, 219, 143, 44, 43, 243, 85, 146, 129, 82, 161, 127, 110, 59, 185, 154, 146, 65, 172, 109, 132, 199, 126, 98, 100, 80, 156, 121, 128, 128, 128, 128, 128, 128, 128, 128, 160, 17, 219, 12, 218, 52, 168, 150, 218, 190, 182, 131, 155, 176, 106, 56, 244, 149, 20, 207, 164, 134, 67, 89, 132, 235, 1, 59, 125, 249, 238, 133, 197, 128, 128},
					{248, 109, 160, 48, 191, 73, 244, 64, 161, 205, 5, 39, 228, 208, 110, 39, 101, 101, 76, 15, 86, 69, 34, 87, 81, 109, 121, 58, 155, 141, 96, 77, 207, 223, 42, 184, 74, 248, 72, 1, 132, 5, 245, 185, 240, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
				Storage: []statediff.StorageDiff{},
			},
		},
	}
	expectedStateDiffBytes, _ := rlp.EncodeToBytes(expectedStateDiff)
	blockChan := make(chan *types.Block)
	parentBlockChain := make(chan *types.Block)
	serviceQuitChan := make(chan bool)
	config := statediff.Config{
		LeafProofs:        true,
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
				NodeType:    statediff.Leaf,
				EncodedPath: burnLeafKey,
				NodeValue:   burnAccount1LeafNode,
				Proof: [][]byte{{248, 113, 160, 87, 118, 82, 182, 37, 183, 123, 219, 91, 247, 123, 196, 63, 49, 37, 202, 215, 70, 77, 103, 157, 21, 117, 86, 82, 119, 211, 97, 27, 128, 83, 231, 128, 128, 128, 128, 160, 254, 136, 159, 16, 229, 219, 143, 44, 43, 243, 85, 146, 129, 82, 161, 127, 110, 59, 185, 154, 146, 65, 172, 109, 132, 199, 126, 98, 100, 80, 156, 121, 128, 128, 128, 128, 128, 128, 128, 128, 160, 17, 219, 12, 218, 52, 168, 150, 218, 190, 182, 131, 155, 176, 106, 56, 244, 149, 20, 207, 164, 134, 67, 89, 132, 235, 1, 59, 125, 249, 238, 133, 197, 128, 128},
					{248, 113, 160, 51, 128, 199, 183, 174, 129, 165, 142, 185, 141, 156, 120, 222, 74, 31, 215, 253, 149, 53, 252, 149, 62, 210, 190, 96, 45, 170, 164, 23, 103, 49, 42, 184, 78, 248, 76, 128, 136, 27, 193, 109, 103, 78, 200, 0, 0, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
				Storage: []statediff.StorageDiff{},
			},
			{
				NodeType:    statediff.Leaf,
				EncodedPath: testhelpers.Account1LeafKey,
				NodeValue:   account1LeafNode,
				Proof: [][]byte{{248, 113, 160, 87, 118, 82, 182, 37, 183, 123, 219, 91, 247, 123, 196, 63, 49, 37, 202, 215, 70, 77, 103, 157, 21, 117, 86, 82, 119, 211, 97, 27, 128, 83, 231, 128, 128, 128, 128, 160, 254, 136, 159, 16, 229, 219, 143, 44, 43, 243, 85, 146, 129, 82, 161, 127, 110, 59, 185, 154, 146, 65, 172, 109, 132, 199, 126, 98, 100, 80, 156, 121, 128, 128, 128, 128, 128, 128, 128, 128, 160, 17, 219, 12, 218, 52, 168, 150, 218, 190, 182, 131, 155, 176, 106, 56, 244, 149, 20, 207, 164, 134, 67, 89, 132, 235, 1, 59, 125, 249, 238, 133, 197, 128, 128},
					{248, 107, 160, 57, 38, 219, 105, 170, 206, 213, 24, 233, 185, 240, 244, 52, 164, 115, 231, 23, 65, 9, 201, 67, 84, 139, 184, 242, 59, 228, 28, 167, 109, 154, 210, 184, 72, 248, 70, 128, 130, 39, 16, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
				Storage: []statediff.StorageDiff{},
			},
		},
		DeletedAccounts: emptyAccountDiffEventualMap,
		UpdatedAccounts: []statediff.AccountDiff{
			{
				NodeType:    statediff.Leaf,
				EncodedPath: testhelpers.BankLeafKey,
				NodeValue:   bankAccount1LeafNode,
				Proof: [][]byte{{248, 113, 160, 87, 118, 82, 182, 37, 183, 123, 219, 91, 247, 123, 196, 63, 49, 37, 202, 215, 70, 77, 103, 157, 21, 117, 86, 82, 119, 211, 97, 27, 128, 83, 231, 128, 128, 128, 128, 160, 254, 136, 159, 16, 229, 219, 143, 44, 43, 243, 85, 146, 129, 82, 161, 127, 110, 59, 185, 154, 146, 65, 172, 109, 132, 199, 126, 98, 100, 80, 156, 121, 128, 128, 128, 128, 128, 128, 128, 128, 160, 17, 219, 12, 218, 52, 168, 150, 218, 190, 182, 131, 155, 176, 106, 56, 244, 149, 20, 207, 164, 134, 67, 89, 132, 235, 1, 59, 125, 249, 238, 133, 197, 128, 128},
					{248, 109, 160, 48, 191, 73, 244, 64, 161, 205, 5, 39, 228, 208, 110, 39, 101, 101, 76, 15, 86, 69, 34, 87, 81, 109, 121, 58, 155, 141, 96, 77, 207, 223, 42, 184, 74, 248, 72, 1, 132, 5, 245, 185, 240, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112}},
				Storage: []statediff.StorageDiff{},
			},
		},
	}
	expectedStateDiffBytes, _ := rlp.EncodeToBytes(expectedStateDiff)
	config := statediff.Config{
		LeafProofs:        true,
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
