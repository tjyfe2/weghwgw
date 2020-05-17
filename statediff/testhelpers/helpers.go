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

package testhelpers

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// MakeChain creates a chain of n blocks starting at and including parent.
// the returned hash chain is ordered head->parent.
func MakeChain(n int, parent *types.Block) ([]*types.Block, *core.BlockChain) {
	config := params.TestChainConfig
	config.EIP158Block = big.NewInt(2)
	config.ByzantiumBlock = big.NewInt(2)
	blocks, _ := core.GenerateChain(config, parent, ethash.NewFaker(), Testdb, n, testChainGen)
	chain, _ := core.NewBlockChain(Testdb, nil, params.TestChainConfig, ethash.NewFaker(), vm.Config{}, nil)
	return blocks, chain
}

func testChainGen(i int, block *core.BlockGen) {
	signer := types.HomesteadSigner{}
	switch i {
	case 0:
		// In block 1, the test bank sends account #1 some ether.
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), Account1Addr, big.NewInt(10000), params.TxGas, nil, nil), signer, TestBankKey)
		block.AddTx(tx)
	case 1:
		// In block 2, the test bank sends some more ether to account #1.
		// account1Addr passes it on to account #2.
		// account1Addr creates a test contract.
		tx1, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), Account1Addr, big.NewInt(1000), params.TxGas, nil, nil), signer, TestBankKey)
		nonce := block.TxNonce(Account1Addr)
		tx2, _ := types.SignTx(types.NewTransaction(nonce, Account2Addr, big.NewInt(1000), params.TxGas, nil, nil), signer, Account1Key)
		nonce++
		tx3, _ := types.SignTx(types.NewContractCreation(nonce, big.NewInt(0), 1000000, big.NewInt(0), ContractCode), signer, Account1Key)
		ContractAddr = crypto.CreateAddress(Account1Addr, nonce) //0xaE9BEa628c4Ce503DcFD7E305CaB4e29E7476592
		block.AddTx(tx1)
		block.AddTx(tx2)
		block.AddTx(tx3)
	case 2:
		// Block 3 has a single tx from the bankAccount to the contract, that transfers no value, that is mined by account2
		block.SetCoinbase(Account2Addr)
		//get function: 60cd2685
		//put function: c16431b9
		//close function: 43d726d6
		data := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003")
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(TestBankAddress), ContractAddr, big.NewInt(0), 100000, nil, data), signer, TestBankKey)
		block.AddTx(tx)
	case 3:
		// Block 4 has two more txs from the bankAccount to the contract, that transfer no value
		// Block is mined by new Account3Addr
		block.SetCoinbase(Account3Addr)
		data1 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000005")
		data2 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002")
		nonce := block.TxNonce(TestBankAddress)
		tx1, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data1), signer, TestBankKey)
		nonce++
		tx2, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data2), signer, TestBankKey)
		block.AddTx(tx1)
		block.AddTx(tx2)
	case 4:
		// Block 5 has two txs from Account3Addr to the contract, that transfer no value and set slot positions to 0
		// Account3Addr then creates a new contract
		// Block is mined by Account2Addr
		block.SetCoinbase(Account2Addr)
		data1 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000")
		data2 := common.Hex2Bytes("C16431B900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000")
		nonce := block.TxNonce(Account3Addr)
		tx1, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data1), signer, Account3Key)
		nonce++
		tx2, _ := types.SignTx(types.NewTransaction(nonce, ContractAddr, big.NewInt(0), 100000, nil, data2), signer, Account3Key)
		block.AddTx(tx1)
		block.AddTx(tx2)
	case 5:
		// Block 6 has a tx which creates a contract with leafkey 2f30668e69d30b6fc1609db5447c101e40dda113ac28be157d20bb61da8e5861
	}
}
