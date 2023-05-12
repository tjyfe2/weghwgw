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
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/internal/e2store"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/urfave/cli/v2"
)

var app = flags.NewApp("go-ethereum e2store tool")

var valueFlag = &cli.BoolFlag{
	Name:  "value",
	Usage: "Print full entry value in hex.",
}

func init() {
	app.Commands = []*cli.Command{
		{
			Name:   "list",
			Usage:  "Lists all entries.",
			Action: list,
		},
		{
			Name:   "find",
			Usage:  "Find the first entry with a specific type.",
			Action: find,
		},
	}
	app.Flags = []cli.Flag{}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// list prints all entries in the store.
func list(ctx *cli.Context) error {
	f, err := open(ctx, 1)
	if err != nil {
		return err
	}
	r := e2store.NewReader(f)

	for {
		entry, err := r.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		s := fmt.Sprintf("type: %d, length: %d", entry.Type, len(entry.Value))
		if ctx.Bool(valueFlag.Name) {
			s += fmt.Sprintf(" value: %s", common.Bytes2Hex(entry.Value))
		}
		fmt.Println(s)
	}
	return nil
}

// find finds the first entry with a matching type.
func find(ctx *cli.Context) error {
	f, err := open(ctx, 2)
	if err != nil {
		return err
	}
	r := e2store.NewReader(f)
	typ, err := strconv.ParseUint(ctx.Args().Get(1), 10, 16)
	if err != nil {
		return fmt.Errorf("error parsing type argument: %w", err)
	}
	entry, err := r.Find(uint16(typ))
	if err == io.EOF {
		fmt.Println("not found")
		return nil
	} else if err != nil {
		return err
	}
	fmt.Printf("%d,%d,%s\n", entry.Type, len(entry.Value), common.Bytes2Hex(entry.Value))
	return nil
}

// open opens the e2store at the provided path.
func open(ctx *cli.Context, argCount int) (*os.File, error) {
	if ctx.Args().Len() != argCount {
		return nil, fmt.Errorf("missing file argument")
	}
	f, err := os.Open(ctx.Args().First())
	if err != nil {
		return nil, fmt.Errorf("error opening e2store: %w", err)
	}
	return f, nil
}
