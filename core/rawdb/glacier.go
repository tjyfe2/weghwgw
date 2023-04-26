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

package rawdb

import (
	"fmt"
	"os"
	"path"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/era"
	"github.com/ethereum/go-ethereum/rlp"
)

type GlacierStore struct {
	head  uint64
	tail  uint64
	eras  map[uint32]*era.Reader
	files map[uint32]*os.File
}

func NewGlacier(datadir, network string) (*GlacierStore, error) {
	var (
		i     = uint32(0)
		files = make(map[uint32]*os.File)
		eras  = make(map[uint32]*era.Reader)
	)
	for ; ; i++ {
		f, err := os.Open(path.Join(era.Filename(int(i), network)))
		if os.IsNotExist(err) && i != 0 {
			break
		} else if err != nil {
			return nil, fmt.Errorf("unable to open era %d: %w", i, err)
		}
		files[i] = f
		eras[i] = era.NewReader(f)
	}

	// Get head block by finding last block in last read era (start+count).
	start, err := eras[i].Start()
	if err != nil {
		return nil, fmt.Errorf("error reading era %d: %w", i, err)
	}
	count, err := eras[i].Count()
	if err != nil {
		return nil, fmt.Errorf("error reading era %d: %w", i, err)
	}
	// Get tail block by finding first block in first read era.
	tail, err := eras[0].Start()
	if err != nil {
		return nil, fmt.Errorf("error reading era %d: %w", i, err)
	}

	return &GlacierStore{
		head:  start + count,
		tail:  tail,
		files: files,
		eras:  eras,
	}, nil
}

func (g *GlacierStore) Close() error {
	var errs []error
	for _, f := range g.files {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

func (g *GlacierStore) Glacier(kind string, number uint64) ([]byte, error) {
	items, err := g.GlacierRange(kind, number, 1, 0)
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

func (g *GlacierStore) GlacierRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	if start < g.tail || start+count > g.head {
		return nil, nil
	}
	var (
		items      [][]byte
		outputSize = 0
	)
	for i := uint64(0); i < count; i++ {
		var (
			number = start + i
			index  = uint32(number / uint64(era.MaxEra1BatchSize))
			b      []byte
		)
		switch kind {
		case ChainFreezerHeaderTable:
			header, err := g.eras[index].ReadHeaderRLP(number)
			if err != nil {
				return nil, fmt.Errorf("error reading header %d from era %d: %w", number, index, err)
			}
			items = append(items, header)
		case ChainFreezerHashTable:
			header, err := g.eras[index].ReadHeaderRLP(number)
			if err != nil {
				return nil, fmt.Errorf("error reading header %d from era %d: %w", number, index, err)
			}
			items = append(items, crypto.Keccak256(header))
		case ChainFreezerBodiesTable:
			body, err := g.eras[index].ReadBodyRLP(number)
			if err != nil {
				return nil, fmt.Errorf("error reading body %d from era %d: %w", number, index, err)
			}
			items = append(items, body)
		case ChainFreezerReceiptTable:
			receipts, err := g.eras[index].ReadReceiptsRLP(number)
			if err != nil {
				return nil, fmt.Errorf("error reading receipts %d from era %d: %w", number, index, err)
			}
			items = append(items, receipts)
		case ChainFreezerDifficultyTable:
			td, err := g.eras[index].ReadTotalDifficulty(number)
			if err != nil {
				return nil, fmt.Errorf("error reading difficulty %d from era %d: %w", number, index, err)
			}
			enc, err := rlp.EncodeToBytes(td)
			if err != nil {
				return nil, fmt.Errorf("error encoding td: %w", err)
			}
			items = append(items, enc)
		default:
			return nil, nil
		}
		if i > 0 && uint64(outputSize+len(b)) > maxBytes {
			break
		}
		outputSize += len(b)
	}
	return items, nil
}
