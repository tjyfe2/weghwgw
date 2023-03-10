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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/e2store"
	"github.com/ethereum/go-ethereum/rlp"
	ssz "github.com/ferranbt/fastssz"
	"github.com/golang/snappy"
)

var (
	TypeVersion           uint16 = 0x3265
	TypeCompressedBlock   uint16 = 0x03
	TypeCompressedReceipt uint16 = 0x04
	TypeAccumulator       uint16 = 0x05
	TypeTotalDifficulty   uint16 = 0x06
	TypeBlockIndex        uint16 = 0x3266

	MaxEraBatchSize = 8192
)

// Filename returns a recognizable Era-formatted file name for the specified
// epoch and network.
func Filename(epoch int, network string) string {
	return fmt.Sprintf("%s-%05d.era", network, epoch)
}

// ComputeAccumulator calculates the SSZ hash tree root of the Era
// accumulator of header records.
func ComputeAccumulator(hashes []common.Hash, tds []*big.Int) (common.Hash, error) {
	if len(hashes) != len(tds) {
		return common.Hash{}, fmt.Errorf("must have equal number hashes as td values")
	}
	hh := ssz.NewHasher()
	for i := range hashes {
		rec := headerRecord{hashes[i], tds[i]}
		root, err := rec.HashTreeRoot()
		if err != nil {
			return common.Hash{}, err
		}
		hh.Append(root[:])
	}
	hh.MerkleizeWithMixin(0, uint64(len(hashes)), uint64(MaxEraBatchSize))
	return hh.HashRoot()
}

// Builder is used to create Era archives of block data.
//
// Era files are themselves e2store files. For more information on this format,
// see https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md.
//
// The overall structure of an Era file can be summarized with this definition:
//
//	era := Version | block-tuple* | other-entries* | Accumulator | StartTD | BlockIndex
//	block-tuple :=  CompressedBlock | CompressedReceipts
//
// Each basic element is its own entry:
//
//	Version            = { type: [0x65, 0x32], data: nil }
//	CompressedBlock    = { type: [0x03, 0x00], data: snappyFramed(rlp(block)) }
//	CompressedReceipts = { type: [0x04, 0x00], data: snappyFramed(rlp(receipts)) }
//	Accumulator        = { type: [0x05, 0x00], data: hash_tree_root(blockHashes, 8192) }
//	StartTD            = { type: [0x06, 0x00], data: uint256(startingTotalDifficulty) }
//	BlockIndex         = { type: [0x32, 0x66], data: block-index }
//
// BlockIndex stores relative offsets to each compressed block entry. The
// format is:
//
//	block-index := starting-number | index | index | index ... | count
//
// starting-number is the first block number in the archive. Every index is a
// defined relative to index's location in the file. The total number of block
// entries in the file is recorded in count.
//
// Due to the accumulator size limit of 8192, the maximum number of blocks in
// an Era batch is also 8192.
type Builder struct {
	w        *e2store.Writer
	startNum *uint64
	startTd  *big.Int
	indexes  []uint64
	hashes   []common.Hash
	tds      []*big.Int
}

// NewBuilder returns a new Builder instance.
func NewBuilder(w io.WriteSeeker) *Builder {
	return &Builder{
		w:      e2store.NewWriter(w),
		hashes: make([]common.Hash, 0),
		tds:    make([]*big.Int, 0),
	}
}

// Add writes a compressed block entry and compressed receipts entry to the
// underlying e2store file.
func (b *Builder) Add(block *types.Block, receipts types.Receipts, td *big.Int) error {
	// Write Era version entry before first block.
	if b.startNum == nil {
		if err := writeVersion(b.w); err != nil {
			return err
		}
		n := block.NumberU64()
		b.startNum = &n
		b.startTd = new(big.Int).Sub(td, block.Difficulty())
	}
	if len(b.indexes) >= MaxEraBatchSize {
		return fmt.Errorf("exceeds maximum batch size of %d", MaxEraBatchSize)
	}

	// Record absolute offset and block hash for entry.
	offset, err := b.w.CurrentOffset()
	if err != nil {
		return err
	}
	b.indexes = append(b.indexes, uint64(offset))
	b.hashes = append(b.hashes, block.Hash())
	b.tds = append(b.tds, td)

	// Write block.
	encBlock, err := rlp.EncodeToBytes(block)
	if err != nil {
		return err
	}
	var (
		buf = bytes.NewBuffer(nil)
		s   = snappy.NewWriter(buf)
	)
	if _, err := s.Write(encBlock); err != nil {
		return fmt.Errorf("error snappy encoding block: %w", err)
	}
	_, err = b.w.Write(TypeCompressedBlock, buf.Bytes())
	if err != nil {
		return err
	}

	// Write receipts.
	encReceipts, err := rlp.EncodeToBytes(receipts)
	if err != nil {
		return err
	}
	buf.Reset()
	s.Reset(buf)
	if _, err := s.Write(encReceipts); err != nil {
		return fmt.Errorf("error snappy encoding receipts: %w", err)
	}
	_, err = b.w.Write(TypeCompressedReceipt, buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// Finalize computes the accumulator and block index values, then writes the
// corresponding e2store entries.
func (b *Builder) Finalize() error {
	if b.startNum == nil {
		return fmt.Errorf("finalize called on empty builder")
	}
	// Compute accumulator root and write entry.
	root, err := ComputeAccumulator(b.hashes, b.tds)
	if err != nil {
		return fmt.Errorf("error calculating accumulator root: %w", err)
	}
	if _, err := b.w.Write(TypeAccumulator, root[:]); err != nil {
		return fmt.Errorf("error writing accumulator: %w", err)
	}

	// Write initial total difficulty.
	td := bigToBytes32(b.startTd)
	if _, err := b.w.Write(TypeTotalDifficulty, td[:]); err != nil {
		return fmt.Errorf("error writing total difficulty: %w", err)
	}

	// Get beginning of index entry to calculate block relative offset.
	base, err := b.w.CurrentOffset()
	if err != nil {
		return err
	}
	base += 3 * 8 // skip e2store header (type, length) and start block

	// Construct block index. Detailed format described in Builder
	// documentation, but it is essentially encoded as:
	// "start | index | index | ... | count"
	var (
		count = len(b.indexes)
		index = make([]byte, 16+count*8)
	)
	binary.LittleEndian.PutUint64(index, *b.startNum)
	// Each offset is relative from the position it is encoded in the
	// index. This means that even if the same block was to be included in
	// the index twice (this would be invalid anyways), the relative offset
	// would be different. The idea with this is that after reading a
	// relative offset, the corresponding block can be quickly read by
	// performing a seek relative to the current position.
	for i, offset := range b.indexes {
		relative := int64(offset) - (base + int64(i)*8)
		binary.LittleEndian.PutUint64(index[8+i*8:], uint64(relative))
	}
	binary.LittleEndian.PutUint64(index[8+count*8:], uint64(count))

	// Finally, write the block index entry.
	if _, err := b.w.Write(TypeBlockIndex, index); err != nil {
		return fmt.Errorf("unable to write block index: %w", err)
	}

	return nil
}

// writeVersion writes a version entry to e2store.
func writeVersion(w *e2store.Writer) error {
	_, err := w.Write(TypeVersion, nil)
	return err
}

// Reader reads an Era archive.
// See Builder documentation for a detailed explanation of the Era format.
type Reader struct {
	r      io.ReadSeekCloser
	offset *uint64
}

// NewReader returns a new Reader instance.
func NewReader(r io.ReadSeekCloser) *Reader {
	return &Reader{r: r}
}

// Read reads one (block, receipts) tuple from an Era archive.
func (r *Reader) Read() (*types.Block, *types.Receipts, error) {
	if r.offset == nil {
		m, err := readMetadata(r)
		if err != nil {
			return nil, nil, err
		}
		r.offset = &m.start
	}
	block, receipts, err := r.ReadBlockAndReceipts(*r.offset)
	if err != nil {
		return nil, nil, err
	}
	*r.offset += 1
	return block, receipts, nil
}

// ReadBlock reads the block number n from the Era archive.
// The method returns error if the Era file is malformed, the request is
// out-of-bounds, as determined by the block index, or if the block number at
// the calculated offset doesn't match the requested.
func (r *Reader) ReadBlock(n uint64) (*types.Block, error) {
	// Read block index metadata.
	m, err := readMetadata(r)
	if err != nil {
		return nil, fmt.Errorf("error reading index: %w", err)
	}
	// Determine if the request can served by current the Era file, e.g. n
	// must be within the range of blocks specified in the block index
	// metadata.
	if n < m.start || m.start+m.count < n {
		return nil, fmt.Errorf("request out-of-bounds: want %d, start: %d, count: %d", n, m.start, m.count)
	}
	// Read the specified block's offset from the block index.
	offset, err := readOffset(r, m, n)
	if err != nil {
		return nil, fmt.Errorf("error reading block offset: %w", err)
	}
	// Read block at offset.
	b, err := readBlockAtOffset(r, offset)
	if b != nil && b.NumberU64() != n {
		return nil, fmt.Errorf("malformed era, wrong block number (want %d, got %d)", n, b.NumberU64())
	}
	return b, err
}

// ReadBlockAndReceipts reads the block number n and associated receipts from
// the Era archive.
//
// The method returns error if the Era file is malformed, the request is
// out-of-bounds, as determined by the block index, or if the block number at
// the calculated offset doesn't match the requested.
func (r *Reader) ReadBlockAndReceipts(n uint64) (*types.Block, *types.Receipts, error) {
	block, err := r.ReadBlock(n)
	if err != nil {
		return nil, nil, err
	}
	receipts, err := readReceipts(r)
	return block, receipts, err
}

// Accumulator reads the accumulator entry in the Era file.
func (r *Reader) Accumulator() (common.Hash, error) {
	_, err := r.seek(0, io.SeekStart)
	entry, err := e2store.NewReader(r.r).Find(TypeAccumulator)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(entry.Value), nil
}

// TotalDifficulty reads the total difficulty entry in the Era file.
func (r *Reader) TotalDifficulty() (*big.Int, error) {
	_, err := r.seek(0, io.SeekStart)
	entry, err := e2store.NewReader(r.r).Find(TypeTotalDifficulty)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(reverseOrder(entry.Value)), nil
}

// Start returns the listed start block.
func (r *Reader) Start() (uint64, error) {
	m, err := readMetadata(r)
	return m.start, err
}

// Count returns the total number of blocks in the Era.
func (r *Reader) Count() (uint64, error) {
	m, err := readMetadata(r)
	return m.count, err
}

// Close implements a closer.
func (r *Reader) Close() error {
	return r.r.Close()
}

// seek is a shorthand method for calling seek on the inner reader.
func (r *Reader) seek(offset int64, whence int) (int64, error) {
	return r.r.Seek(offset, whence)
}

// metadata wraps the metadata in the block index.
type metadata struct {
	start, count uint64
}

// readMetadata reads the metadata stored in an Era file's block index.
func readMetadata(r *Reader) (m metadata, err error) {
	// Seek to count.
	if _, err = r.seek(-8, io.SeekEnd); err != nil {
		return
	}
	// Read count.
	if err = binary.Read(r.r, binary.LittleEndian, &m.count); err != nil {
		return
	}
	// Seek to start.
	if _, err = r.seek(-16-int64(m.count)*8, io.SeekEnd); err != nil {
		return
	}
	// Read start.
	if err = binary.Read(r.r, binary.LittleEndian, &m.start); err != nil {
		return
	}
	return
}

// readOffset reads a specific block's offset from the block index. The value n
// is the absolute block number desired. It is normalized against the index's
// start block.
func readOffset(r *Reader, m metadata, n uint64) (int64, error) {
	// Seek to the encoding of the block's offset.
	var (
		firstIndex  = -8 - int64(m.count)*8 // size of count - index entries
		indexOffset = int64(n-m.start) * 8  // desired index * size of indexes
	)
	if _, err := r.r.Seek(firstIndex+indexOffset, io.SeekEnd); err != nil {
		return 0, err
	}
	// Read the block's offset.
	var offset int64
	if err := binary.Read(r.r, binary.LittleEndian, &offset); err != nil {
		return 0, err
	}
	return offset, nil
}

// readBlockAtOffset reads a snappy encoded block at the specified offset.
//
// Note that offset is relative to the current cursor location in the reader.
// It should only be called immediately after readOffset.
func readBlockAtOffset(r *Reader, offset int64) (*types.Block, error) {
	// Seek to beginning of block entry.
	if _, err := r.r.Seek(offset, io.SeekCurrent); err != nil {
		return nil, err
	}
	// Read e2store entry.
	entry, err := e2store.NewReader(r.r).Read()
	if err != nil {
		return nil, err
	}
	if entry.Type != TypeCompressedBlock {
		return nil, fmt.Errorf("expected block entry, got %x", entry.Type)
	}
	// Read block from snappy framing.
	b, err := io.ReadAll(snappy.NewReader(bytes.NewReader(entry.Value)))
	if err != nil {
		return nil, fmt.Errorf("error decoding snappy: %w", err)
	}
	var block types.Block
	if err := rlp.DecodeBytes(b, &block); err != nil {
		return nil, fmt.Errorf("error decoding block: %w", err)
	}
	return &block, nil
}

// readReceipts reads a snappy encoded list of receipts.
//
// Note, this method expects the file cursor to be located at the beginning of
// the e2store entry for the receipts, and so it should generally be called
// after readBlockAtOffset.
func readReceipts(r *Reader) (*types.Receipts, error) {
	// Read e2store entry.
	entry, err := e2store.NewReader(r.r).Read()
	if err != nil {
		return nil, err
	}
	if entry.Type != TypeCompressedReceipt {
		return nil, fmt.Errorf("expected receipts entry, got %x", entry.Type)
	}
	// Read block from snappy framing.
	b, err := io.ReadAll(snappy.NewReader(bytes.NewReader(entry.Value)))
	if err != nil {
		return nil, fmt.Errorf("error decoding snappy: %w", err)
	}
	var receipts types.Receipts
	if err := rlp.DecodeBytes(b, &receipts); err != nil {
		return nil, fmt.Errorf("error decoding block: %w", err)
	}
	return &receipts, nil
}

// headerRecord is an individual record for a historical header.
//
// See https://github.com/ethereum/portal-network-specs/blob/master/history-network.md#the-header-accumulator
// for more information.
type headerRecord struct {
	Hash            common.Hash
	TotalDifficulty *big.Int
}

// GetTree completes the ssz.HashRoot interface, but is unused.
func (h *headerRecord) GetTree() (*ssz.Node, error) {
	return nil, nil
}

// HashTreeRoot ssz hashes the headerRecord object.
func (h *headerRecord) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(h)
}

// HashTreeRootWith ssz hashes the headerRecord object with a hasher.
func (h *headerRecord) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	hh.PutBytes(h.Hash[:])
	td := bigToBytes32(h.TotalDifficulty)
	hh.PutBytes(td[:])
	hh.Merkleize(0)
	return
}

// bigToBytes32 converts a big.Int into a little-endian 32-byte array.
func bigToBytes32(n *big.Int) (b [32]byte) {
	n.FillBytes(b[:])
	reverseOrder(b[:])
	return
}

// reverseOrder reverses the byte order of a slice.
func reverseOrder(b []byte) []byte {
	for i := 0; i < 16; i++ {
		b[i], b[32-i-1] = b[32-i-1], b[i]
	}
	return b
}
