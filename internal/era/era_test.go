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
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

func makeTestChain() ([]*types.Block, []types.Receipts) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		genesis = &core.Genesis{
			Config: params.TestChainConfig,
			Alloc:  core.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000000)}},
		}
		signer = types.LatestSigner(genesis.Config)
	)
	_, b, r := core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), 16, func(i int, g *core.BlockGen) {
		if i == 0 {
			return
		}
		tx, _ := types.SignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID:    genesis.Config.ChainID,
			Nonce:      uint64(i - 1),
			GasTipCap:  common.Big0,
			GasFeeCap:  g.PrevBlock(0).BaseFee(),
			Gas:        50000,
			To:         &common.Address{0xaa},
			Value:      big.NewInt(int64(i)),
			Data:       nil,
			AccessList: nil,
		})
		g.AddTx(tx)
	})
	return b, r
}

func TestEraBuilder(t *testing.T) {
	// Get temp directory.
	f, err := os.CreateTemp("", "era-test")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer f.Close()

	var (
		blocks, receipts = makeTestChain()
		builder          = NewBuilder(f)
	)

	// Write blocks to Era.
	for i := range blocks {
		if err := builder.Add(blocks[i], receipts[i]); err != nil {
			t.Fatalf("error adding entry: %v", err)
		}
	}

	// Finalize Era.
	if err := builder.Finalize(); err != nil {
		t.Fatalf("error finalizing era: %v", err)
	}

	// Verify Era contents.
	r := NewReader(f)
	for _, want := range blocks {
		got, err := r.ReadBlock(want.NumberU64())
		if err != nil {
			t.Fatalf("error reading block from era: %v", err)
		}
		if got, want := got.Hash(), want.Hash(); got != want {
			t.Fatalf("unexpected block (want %s, got %s)", want.Hex(), got.Hex())
		}
	}
}
