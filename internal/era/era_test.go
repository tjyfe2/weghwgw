// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package era

import (
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

func makeTestChain(blocks, maxTx, minTx int) *core.BlockChain {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		genesis = &core.Genesis{
			Config:   params.TestChainConfig,
			GasLimit: 30_000_000,
			Alloc:    core.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000000)}},
		}
		signer = types.LatestSigner(genesis.Config)
	)
	db, b, _ := core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), blocks, func(i int, g *core.BlockGen) {
		if i == 0 {
			return
		}
		var (
			count = minTx + (int(rand.Uint64()) % (maxTx - minTx + 1))
			sum   = uint64(0)
		)

		for j := 0; j < count; j++ {
			data := make([]byte, 512)
			if _, err := rand.Read(data); err != nil {
				panic(err)
			}
			gas, _ := core.IntrinsicGas(data, nil, false, true, true, true)
			if sum > g.PrevBlock(int(g.Number().Int64())-2).GasLimit() {
				break
			}
			tx, _ := types.SignNewTx(key, signer, &types.DynamicFeeTx{
				ChainID:    genesis.Config.ChainID,
				Nonce:      uint64(g.TxNonce(address)),
				GasTipCap:  common.Big0,
				GasFeeCap:  g.PrevBlock(0).BaseFee(),
				Gas:        gas,
				To:         &common.Address{0xaa},
				Value:      big.NewInt(int64(i)),
				Data:       data,
				AccessList: nil,
			})
			sum += gas
			g.AddTx(tx)
		}
	})
	chain, _ := core.NewBlockChain(db, nil, genesis, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	chain.InsertChain(b)
	return chain
}

func TestEraBuilder(t *testing.T) {
	// Get temp directory.
	f, err := os.CreateTemp("", "era-test")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer f.Close()

	var (
		chain   = makeTestChain(128, 1, 1)
		builder = NewBuilder(f)
	)

	// Write blocks to Era.
	head := chain.CurrentBlock().Number.Uint64()
	for i := uint64(0); i < head; i++ {
		var (
			block    = chain.GetBlockByNumber(i)
			receipts = chain.GetReceiptsByHash(block.Hash())
			td       = chain.GetTd(block.Hash(), i)
		)
		if err := builder.Add(block, receipts, td); err != nil {
			t.Fatalf("error adding entry: %v", err)
		}
	}

	// Finalize Era.
	if err := builder.Finalize(); err != nil {
		t.Fatalf("error finalizing era: %v", err)
	}

	// Verify Era contents.
	r := NewReader(f)
	if err := r.Verify(); err != nil {
		t.Fatalf("invalid era: %v", err)
	}
	for i := uint64(0); i < head; i++ {
		want := chain.GetBlockByNumber(i)
		b, r, err := r.ReadBlockAndReceipts(want.NumberU64())
		if err != nil {
			t.Fatalf("error reading block from era: %v", err)
		}
		if want, got := want.NumberU64(), b.NumberU64(); want != got {
			t.Fatalf("blocks out of order: want %d, got %d", want, got)
		}
		if want.Hash() != b.Hash() {
			t.Fatalf("block hash mistmatch %d: want %s, got %s", want.NumberU64(), want.Hash().Hex(), b.Hash().Hex())
		}
		if got := types.DeriveSha(r, trie.NewStackTrie(nil)); got != want.ReceiptHash() {
			t.Fatalf("receipt root %d mismatch: want %s, got %s", want.NumberU64(), want.ReceiptHash(), got)
		}
	}
}

func makeEra() (*os.File, error) {
	f, err := os.CreateTemp("", "era-test")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file: %w", err)
	}
	var (
		chain   = makeTestChain(128, 512, 128)
		builder = NewBuilder(f)
	)
	head := chain.CurrentBlock().Number.Uint64()
	for i := uint64(0); i < head; i++ {
		var (
			block    = chain.GetBlockByNumber(i)
			receipts = chain.GetReceiptsByHash(block.Hash())
			td       = chain.GetTd(block.Hash(), i)
		)
		if err := builder.Add(block, receipts, td); err != nil {
			return nil, fmt.Errorf("error adding entry: %w", err)
		}
	}
	if err := builder.Finalize(); err != nil {
		return nil, fmt.Errorf("error finalizing era: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek failed")
	}
	return f, nil
}

var allBlocks []*types.Block
var allReceipts []types.Receipts

func BenchmarkRead(b *testing.B) {
	f, err := makeEra()
	if err != nil {
		f.Close()
		b.Fatalf("%v", err)
	}
	defer f.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := NewReader(f)
		for {
			if bb, rr, err := r.Read(); err == io.EOF {
				break
			} else if err != nil {
				b.Fatalf("error reading era: %v", err)
			} else {
				allBlocks = append(allBlocks, bb)
				allReceipts = append(allReceipts, rr)
			}
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	f, err := makeEra()
	if err != nil {
		f.Close()
		b.Fatalf("%v", err)
	}
	defer f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := NewReader(f)
		if err := r.Verify(); err != nil {
			b.Fatalf("error verifying era: %v", err)
		}
	}
}

func BenchmarkHash(b *testing.B) {
	f, err := makeEra()
	if err != nil {
		f.Close()
		b.Fatalf("%v", err)
	}
	defer f.Close()
	data, _ := io.ReadAll(f)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.Keccak256(data)
	}
}
