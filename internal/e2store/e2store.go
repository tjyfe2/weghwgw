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

package e2store

import (
	"bufio"
	"fmt"
	"io"
)

var headerSize = 8

// Entry is a variable-length-data record in an e2store.
type Entry struct {
	Type  uint16
	Value []byte
}

// Writer writes entries using e2store encoding.
// For more information on this format, see
// https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md
type Writer struct {
	w io.WriteSeeker
}

// NewWriter returns a new Writer that writes to w.
func NewWriter(w io.WriteSeeker) *Writer {
	return &Writer{w}
}

// Write writes a single e2store entry to w.
// An entry is encoded in a type-length-value format. The first 8 bytes of the
// record store the type (2 bytes) and the length (6 bytes). The remaining
// bytes store b.
func (w *Writer) Write(typ uint16, b []byte) (int, error) {
	buf := make([]byte, headerSize+len(b))

	// type
	buf[0] = byte(typ)
	buf[1] = byte(typ >> 8)

	// length
	l := len(b)
	buf[2] = byte(l)
	buf[3] = byte(l >> 8)
	buf[4] = byte(l >> 16)
	buf[5] = byte(l >> 24)
	buf[6] = byte(l >> 32)
	buf[7] = byte(l >> 40)

	// value
	copy(buf[8:], b)

	return w.w.Write(buf)
}

// CurrentOffset returns the current offset of the underlying writer.
func (w *Writer) CurrentOffset() (int64, error) {
	return w.w.Seek(0, io.SeekCurrent)
}

// A Reader reads entries from an e2store-encoded file.
// For more information on this format, see
// https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md
type Reader struct {
	r *bufio.Reader
}

// NewReader returns a new Reader that reads from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		r: bufio.NewReader(r),
	}
}

// Read reads one Entry from r.
// If the entry is malformed, it returns io.UnexpectedEOF. If there are no
// entries left to be read, Read returns io.EOF.
func (r *Reader) Read() (*Entry, error) {
	b := make([]byte, headerSize)
	if _, err := io.ReadFull(r.r, b); err != nil {
		return nil, err
	}

	typ := uint16(b[0])
	typ += uint16(b[1]) << 8

	length := uint64(b[2])
	length += uint64(b[3]) << 8
	length += uint64(b[4]) << 16
	length += uint64(b[5]) << 24
	length += uint64(b[6]) << 32
	length += uint64(b[7]) << 40
	fmt.Println(typ, length)

	val := make([]byte, length)
	if _, err := io.ReadFull(r.r, val); err != nil {
		// An entry with a non-zero length should not return EOF when
		// reading the value.
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}

	return &Entry{
		Type:  typ,
		Value: val,
	}, nil
}
