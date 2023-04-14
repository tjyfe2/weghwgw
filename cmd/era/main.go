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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/era"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/urfave/cli/v2"
)

var app = flags.NewApp("go-ethereum era tool")

var (
	dirFlag = &cli.StringFlag{
		Name:  "dir",
		Usage: "directory storing all relevant Era files",
		Value: "eras",
	}
	networkFlag = &cli.StringFlag{
		Name:  "network",
		Usage: "network name associated with Era files",
		Value: "mainnet",
	}
	batchSizeFlag = &cli.IntFlag{
		Name:  "batchSize",
		Usage: "number blocks per era batch",
		Value: era.MaxEra1BatchSize,
	}
	txsFlag = &cli.BoolFlag{
		Name:  "txs",
		Usage: "print full transaction values",
	}
)

var (
	blockCommand = &cli.Command{
		Name:      "block",
		Usage:     "get block data",
		ArgsUsage: "<number>",
		Action:    block,
		Flags: []cli.Flag{
			txsFlag,
		},
	}
	infoCommand = &cli.Command{
		Name:      "info",
		ArgsUsage: "<epoch>",
		Usage:     "get epoch information",
		Action:    info,
	}
	verifyCommand = &cli.Command{
		Name:      "verify",
		ArgsUsage: "<expected>",
		Usage:     "verifies each epoch against expected accumulator root",
		Action:    verify,
	}
	rewriteCommand = &cli.Command{
		Name:      "rewrite",
		ArgsUsage: "<era> <count>",
		Usage:     "rewrites the era starting the blocks at 1",
		Action:    rewrite,
	}
)

func init() {
	app.Commands = []*cli.Command{
		blockCommand,
		infoCommand,
		verifyCommand,
		rewriteCommand,
	}
	app.Flags = []cli.Flag{
		dirFlag,
		networkFlag,
		batchSizeFlag,
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// block prints the specified block from an Era store.
func block(ctx *cli.Context) error {
	num, err := strconv.ParseUint(ctx.Args().First(), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid block number: %w", err)
	}

	r, err := openEra1(ctx, num/uint64(ctx.Int(batchSizeFlag.Name)))
	if err != nil {
		return fmt.Errorf("error opening era: %w", err)
	}

	// Read block with number.
	block, err := r.ReadBlock(num)
	if err != nil {
		return fmt.Errorf("error reading era: %w", err)
	}

	// Convert block to JSON and print.
	val, err := ethapi.RPCMarshalBlock(block, ctx.Bool(txsFlag.Name), ctx.Bool(txsFlag.Name), params.MainnetChainConfig)
	if err != nil {
		return fmt.Errorf("error marshaling json: %w", err)
	}
	b, err := json.MarshalIndent(val, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling json: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

// info prints some high-level information about the Era file.
func info(ctx *cli.Context) error {
	epoch, err := strconv.ParseUint(ctx.Args().First(), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid block number: %w", err)
	}
	era, err := openEra1(ctx, epoch)
	if err != nil {
		return err
	}

	acc, err := era.Accumulator()
	if err != nil {
		return fmt.Errorf("error reading accumulator: %w", err)
	}
	td, err := era.TotalDifficulty()
	if err != nil {
		return fmt.Errorf("error reading total difficulty: %w", err)
	}
	start, err := era.Start()
	if err != nil {
		return fmt.Errorf("error reading start block: %w", err)
	}
	count, err := era.Count()
	if err != nil {
		return fmt.Errorf("error reading count: %w", err)
	}
	info := struct {
		Accumulator     common.Hash `json:"accumulator"`
		TotalDifficulty *big.Int    `json:"totalDifficulty"`
		StartBlock      uint64      `json:"startBlock"`
		Count           uint64      `json:"count"`
	}{
		acc, td, start, count,
	}
	b, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(b))
	return nil
}

// openEra1 opens an Era file at a certain epoch.
func openEra1(ctx *cli.Context, epoch uint64) (*era.Reader, error) {
	var (
		dir     = ctx.String(dirFlag.Name)
		network = ctx.String(networkFlag.Name)
	)
	filename := path.Join(dir, era.Filename(int(epoch), network))
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening era dir: %w", err)
	}
	return era.NewReader(f), nil
}

// verify checks each Era1 file in a directory to ensure it is well-formed and
// that the accumulator matches the expected value.
func verify(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		return fmt.Errorf("missing accumulators file")
	}

	roots, err := readHashes(ctx.Args().First())
	if err != nil {
		return fmt.Errorf("unable to read expected roots file: %w", err)
	}

	var (
		dir      = ctx.String(dirFlag.Name)
		network  = ctx.String(networkFlag.Name)
		start    = time.Now()
		reported = time.Now()
	)

	// Verify each epoch matches the expected root.
	for i, want := range roots {
		name := path.Join(dir, era.Filename(i, network))
		f, err := os.Open(name)
		if err != nil {
			return fmt.Errorf("error opening era1 file %s: %w", name, err)
		}
		defer f.Close()

		r := era.NewReader(f)

		// Read accumulator and check against expected.
		if got, err := r.Accumulator(); err != nil {
			return fmt.Errorf("error retrieving accumulator for %s: %w", name, err)
		} else if got != want {
			return fmt.Errorf("invalid root %s: got %s, want %s", name, got, want)
		}

		// Recompute accumulator.
		if err := r.Verify(); err != nil {
			return fmt.Errorf("error verify era1 file %s: %w", name, err)
		}

		// Give the user some feedback that something is happening.
		if time.Since(reported) >= 8*time.Second {
			fmt.Printf("Verifying Era1 files \t\t verified=%d,\t elapsed=%s\n", i, common.PrettyDuration(time.Since(start)))
			reported = time.Now()
		}
	}

	return nil
}

func rewrite(ctx *cli.Context) error {
	if ctx.Args().Len() != 2 {
		return fmt.Errorf("usage: era rewrite <era> <count>")
	}
	start, err := strconv.ParseUint(ctx.Args().First(), 10, 64)
	if err != nil {
		return fmt.Errorf("start value must be integer")
	}
	count, err := strconv.ParseUint(ctx.Args().Get(1), 10, 64)
	if err != nil {
		return fmt.Errorf("count value must be integer")
	}
	var (
		n       = uint64(0)
		dir     = ctx.String(dirFlag.Name)
		network = ctx.String(networkFlag.Name)
		genesis = core.DefaultGenesisBlock().ToBlock()
		td      = genesis.Difficulty()
		last    common.Hash
	)
	for i := uint64(0); i < count; i++ {
		buf, err := os.ReadFile(path.Join(dir, era.Filename(int(start+i), network)))
		if err != nil {
			return err
		}
		f, err := os.Create(path.Join(dir, era.Filename(int(i), network)))
		if err != nil {
			return fmt.Errorf("unable to create era %d: %w", i, err)
		}
		defer f.Close()
		var (
			r = era.NewReader(bytes.NewReader(buf))
			b = era.NewBuilder(f)
		)
		for {
			block, receipts, err := r.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("error reading era %d: %w", start+i, err)
			} else if n == 0 {
				// special case for genesis
				block = genesis
				receipts = nil
			}
			header := block.Header()
			header.Number.SetUint64(n)
			header.ParentHash = last
			block = types.NewBlock(header, block.Transactions(), block.Uncles(), receipts, trie.NewStackTrie(nil))
			if err := b.Add(block, receipts, td); err != nil {
				return fmt.Errorf("error adding to era %d: %w", start+i, err)
			}
			last = block.Hash()
			td = td.Add(td, block.Difficulty())
			n += 1
		}
		if err := b.Finalize(); err != nil {
			return fmt.Errorf("error finalizing era %d: %w", start+i, err)
		}
	}
	return nil
}

// readHashes reads a file of newline-delimited hashes.
func readHashes(f string) ([]common.Hash, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("unable to open accumulators file")
	}
	s := strings.Split(string(b), "\n")
	// Remove empty last element, if present.
	if s[len(s)-1] == "" {
		s = s[:len(s)-1]
	}
	// Convert to hashes.
	r := make([]common.Hash, len(s))
	for i := range s {
		r[i] = common.HexToHash(s[i])
	}
	return r, nil
}
