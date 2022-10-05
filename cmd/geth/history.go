// Copyright 2022 The go-ethereum Authors
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
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/urfave/cli/v2"
)

var (
	historyCommand = &cli.Command{
		Name:        "history",
		Usage:       "A set of experimental history management commands",
		Category:    "MISCELLANEOUS COMMANDS",
		Description: "",
		Subcommands: []*cli.Command{
			{
				Name:      "export",
				Usage:     "export chain into verifiable format",
				ArgsUsage: "<root>",
				Action:    exportHistory,
				Flags:     append(flags.Merge(utils.DatabasePathFlags), utils.ExportTargetSizeFlag),
				Description: `
geth history export <filename>

Requires a first argument of the file to write to. If -targetSize option is present, 
output is split into sequential numbered files capped at (approximately) that size.
Optional second and third arguments control the first and last block to write.
`,
			},
		},
	}
)

func exportHistory(ctx *cli.Context) error {
	if ctx.Args().Len() < 1 {
		utils.Fatalf("This command requires an argument.")
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, _ := utils.MakeChain(ctx, stack)
	start := time.Now()

	var err error
	fp := ctx.Args().First()
	targetSize := ctx.Int(utils.ExportTargetSizeFlag.Name)
	if ctx.Args().Len() < 3 {
		err = utils.ExportHistory(chain, fp, targetSize)
	} else {
		// This can be improved to allow for numbers larger than 9223372036854775807
		first, ferr := strconv.ParseInt(ctx.Args().Get(1), 10, 64)
		last, lerr := strconv.ParseInt(ctx.Args().Get(2), 10, 64)
		if ferr != nil || lerr != nil {
			utils.Fatalf("Export error in parsing parameters: block number not an integer\n")
		}
		if first < 0 || last < 0 {
			utils.Fatalf("Export error: block number must be greater than 0\n")
		}
		if last <= first {
			utils.Fatalf("Export error: last block must be greater than first block\n")
		}
		if head := chain.CurrentFastBlock(); uint64(last) > head.NumberU64() {
			utils.Fatalf("Export error: block number %d larger than head block %d\n", uint64(last), head.NumberU64())
		}
		err = utils.ExportHistoryRange(chain, fp, uint64(first), uint64(last), targetSize)
	}

	if err != nil {
		utils.Fatalf("Export error: %v\n", err)
	}
	fmt.Printf("Export done in %v\n", time.Since(start))
	return nil
}
