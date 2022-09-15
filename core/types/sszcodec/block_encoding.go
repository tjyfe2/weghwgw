// Code generated by fastssz. DO NOT EDIT.
// Hash: 79d8a2eb266b90c26a1b72270e9e4d42e586c85102262a394fbd5aed7764a2bb
// Version: 0.1.2
package sszcodec

import (
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the Block object
func (b *Block) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(b)
}

// MarshalSSZTo ssz marshals the Block object to a target array
func (b *Block) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(16)

	// Offset (0) 'Header'
	dst = ssz.WriteOffset(dst, offset)
	if b.Header == nil {
		b.Header = new(Header)
	}
	offset += b.Header.SizeSSZ()

	// Offset (1) 'Transactions'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(b.Transactions); ii++ {
		offset += 4
		offset += len(b.Transactions[ii])
	}

	// Offset (2) 'Uncles'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(b.Uncles); ii++ {
		offset += 4
		offset += b.Uncles[ii].SizeSSZ()
	}

	// Offset (3) 'Receipts'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(b.Receipts); ii++ {
		offset += 4
		offset += b.Receipts[ii].SizeSSZ()
	}

	// Field (0) 'Header'
	if dst, err = b.Header.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (1) 'Transactions'
	if size := len(b.Transactions); size > 1048576 {
		err = ssz.ErrListTooBigFn("Block.Transactions", size, 1048576)
		return
	}
	{
		offset = 4 * len(b.Transactions)
		for ii := 0; ii < len(b.Transactions); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += len(b.Transactions[ii])
		}
	}
	for ii := 0; ii < len(b.Transactions); ii++ {
		if size := len(b.Transactions[ii]); size > 1073741824 {
			err = ssz.ErrBytesLengthFn("Block.Transactions[ii]", size, 1073741824)
			return
		}
		dst = append(dst, b.Transactions[ii]...)
	}

	// Field (2) 'Uncles'
	if size := len(b.Uncles); size > 6040 {
		err = ssz.ErrListTooBigFn("Block.Uncles", size, 6040)
		return
	}
	{
		offset = 4 * len(b.Uncles)
		for ii := 0; ii < len(b.Uncles); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += b.Uncles[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(b.Uncles); ii++ {
		if dst, err = b.Uncles[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (3) 'Receipts'
	if size := len(b.Receipts); size > 4194452 {
		err = ssz.ErrListTooBigFn("Block.Receipts", size, 4194452)
		return
	}
	{
		offset = 4 * len(b.Receipts)
		for ii := 0; ii < len(b.Receipts); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += b.Receipts[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(b.Receipts); ii++ {
		if dst, err = b.Receipts[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the Block object
func (b *Block) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 16 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1, o2, o3 uint64

	// Offset (0) 'Header'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 16 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'Transactions'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Offset (2) 'Uncles'
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Offset (3) 'Receipts'
	if o3 = ssz.ReadOffset(buf[12:16]); o3 > size || o2 > o3 {
		return ssz.ErrOffset
	}

	// Field (0) 'Header'
	{
		buf = tail[o0:o1]
		if b.Header == nil {
			b.Header = new(Header)
		}
		if err = b.Header.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (1) 'Transactions'
	{
		buf = tail[o1:o2]
		num, err := ssz.DecodeDynamicLength(buf, 1048576)
		if err != nil {
			return err
		}
		b.Transactions = make([][]byte, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if len(buf) > 1073741824 {
				return ssz.ErrBytesLength
			}
			if cap(b.Transactions[indx]) == 0 {
				b.Transactions[indx] = make([]byte, 0, len(buf))
			}
			b.Transactions[indx] = append(b.Transactions[indx], buf...)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (2) 'Uncles'
	{
		buf = tail[o2:o3]
		num, err := ssz.DecodeDynamicLength(buf, 6040)
		if err != nil {
			return err
		}
		b.Uncles = make([]*Header, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if b.Uncles[indx] == nil {
				b.Uncles[indx] = new(Header)
			}
			if err = b.Uncles[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (3) 'Receipts'
	{
		buf = tail[o3:]
		num, err := ssz.DecodeDynamicLength(buf, 4194452)
		if err != nil {
			return err
		}
		b.Receipts = make([]*Receipt, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if b.Receipts[indx] == nil {
				b.Receipts[indx] = new(Receipt)
			}
			if err = b.Receipts[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Block object
func (b *Block) SizeSSZ() (size int) {
	size = 16

	// Field (0) 'Header'
	if b.Header == nil {
		b.Header = new(Header)
	}
	size += b.Header.SizeSSZ()

	// Field (1) 'Transactions'
	for ii := 0; ii < len(b.Transactions); ii++ {
		size += 4
		size += len(b.Transactions[ii])
	}

	// Field (2) 'Uncles'
	for ii := 0; ii < len(b.Uncles); ii++ {
		size += 4
		size += b.Uncles[ii].SizeSSZ()
	}

	// Field (3) 'Receipts'
	for ii := 0; ii < len(b.Receipts); ii++ {
		size += 4
		size += b.Receipts[ii].SizeSSZ()
	}

	return
}

// HashTreeRoot ssz hashes the Block object
func (b *Block) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

// HashTreeRootWith ssz hashes the Block object with a hasher
func (b *Block) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Header'
	if err = b.Header.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Transactions'
	{
		subIndx := hh.Index()
		num := uint64(len(b.Transactions))
		if num > 1048576 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.Transactions {
			{
				elemIndx := hh.Index()
				byteLen := uint64(len(elem))
				if byteLen > 1073741824 {
					err = ssz.ErrIncorrectListSize
					return
				}
				hh.AppendBytes32(elem)
				hh.MerkleizeWithMixin(elemIndx, byteLen, (1073741824+31)/32)
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 1048576)
	}

	// Field (2) 'Uncles'
	{
		subIndx := hh.Index()
		num := uint64(len(b.Uncles))
		if num > 6040 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.Uncles {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 6040)
	}

	// Field (3) 'Receipts'
	{
		subIndx := hh.Index()
		num := uint64(len(b.Receipts))
		if num > 4194452 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range b.Receipts {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 4194452)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Block object
func (b *Block) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(b)
}

// MarshalSSZ ssz marshals the Header object
func (h *Header) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(h)
}

// MarshalSSZTo ssz marshals the Header object to a target array
func (h *Header) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(576)

	// Field (0) 'ParentHash'
	if size := len(h.ParentHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.ParentHash", size, 32)
		return
	}
	dst = append(dst, h.ParentHash...)

	// Field (1) 'UncleHash'
	if size := len(h.UncleHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.UncleHash", size, 32)
		return
	}
	dst = append(dst, h.UncleHash...)

	// Field (2) 'FeeRecipient'
	if size := len(h.FeeRecipient); size != 20 {
		err = ssz.ErrBytesLengthFn("Header.FeeRecipient", size, 20)
		return
	}
	dst = append(dst, h.FeeRecipient...)

	// Field (3) 'StateRoot'
	if size := len(h.StateRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.StateRoot", size, 32)
		return
	}
	dst = append(dst, h.StateRoot...)

	// Field (4) 'TxHash'
	if size := len(h.TxHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.TxHash", size, 32)
		return
	}
	dst = append(dst, h.TxHash...)

	// Field (5) 'ReceiptsRoot'
	if size := len(h.ReceiptsRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.ReceiptsRoot", size, 32)
		return
	}
	dst = append(dst, h.ReceiptsRoot...)

	// Field (6) 'LogsBloom'
	if size := len(h.LogsBloom); size != 256 {
		err = ssz.ErrBytesLengthFn("Header.LogsBloom", size, 256)
		return
	}
	dst = append(dst, h.LogsBloom...)

	// Field (7) 'Difficulty'
	if size := len(h.Difficulty); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.Difficulty", size, 32)
		return
	}
	dst = append(dst, h.Difficulty...)

	// Field (8) 'BlockNumber'
	dst = ssz.MarshalUint64(dst, h.BlockNumber)

	// Field (9) 'GasLimit'
	dst = ssz.MarshalUint64(dst, h.GasLimit)

	// Field (10) 'GasUsed'
	dst = ssz.MarshalUint64(dst, h.GasUsed)

	// Field (11) 'Timestamp'
	dst = ssz.MarshalUint64(dst, h.Timestamp)

	// Offset (12) 'ExtraData'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(h.ExtraData)

	// Field (13) 'BaseFeePerGas'
	if size := len(h.BaseFeePerGas); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.BaseFeePerGas", size, 32)
		return
	}
	dst = append(dst, h.BaseFeePerGas...)

	// Field (14) 'MixDigest'
	if size := len(h.MixDigest); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.MixDigest", size, 32)
		return
	}
	dst = append(dst, h.MixDigest...)

	// Field (15) 'Nonce'
	if size := len(h.Nonce); size != 8 {
		err = ssz.ErrBytesLengthFn("Header.Nonce", size, 8)
		return
	}
	dst = append(dst, h.Nonce...)

	// Field (12) 'ExtraData'
	if size := len(h.ExtraData); size > 32 {
		err = ssz.ErrBytesLengthFn("Header.ExtraData", size, 32)
		return
	}
	dst = append(dst, h.ExtraData...)

	return
}

// UnmarshalSSZ ssz unmarshals the Header object
func (h *Header) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 576 {
		return ssz.ErrSize
	}

	tail := buf
	var o12 uint64

	// Field (0) 'ParentHash'
	if cap(h.ParentHash) == 0 {
		h.ParentHash = make([]byte, 0, len(buf[0:32]))
	}
	h.ParentHash = append(h.ParentHash, buf[0:32]...)

	// Field (1) 'UncleHash'
	if cap(h.UncleHash) == 0 {
		h.UncleHash = make([]byte, 0, len(buf[32:64]))
	}
	h.UncleHash = append(h.UncleHash, buf[32:64]...)

	// Field (2) 'FeeRecipient'
	if cap(h.FeeRecipient) == 0 {
		h.FeeRecipient = make([]byte, 0, len(buf[64:84]))
	}
	h.FeeRecipient = append(h.FeeRecipient, buf[64:84]...)

	// Field (3) 'StateRoot'
	if cap(h.StateRoot) == 0 {
		h.StateRoot = make([]byte, 0, len(buf[84:116]))
	}
	h.StateRoot = append(h.StateRoot, buf[84:116]...)

	// Field (4) 'TxHash'
	if cap(h.TxHash) == 0 {
		h.TxHash = make([]byte, 0, len(buf[116:148]))
	}
	h.TxHash = append(h.TxHash, buf[116:148]...)

	// Field (5) 'ReceiptsRoot'
	if cap(h.ReceiptsRoot) == 0 {
		h.ReceiptsRoot = make([]byte, 0, len(buf[148:180]))
	}
	h.ReceiptsRoot = append(h.ReceiptsRoot, buf[148:180]...)

	// Field (6) 'LogsBloom'
	if cap(h.LogsBloom) == 0 {
		h.LogsBloom = make([]byte, 0, len(buf[180:436]))
	}
	h.LogsBloom = append(h.LogsBloom, buf[180:436]...)

	// Field (7) 'Difficulty'
	if cap(h.Difficulty) == 0 {
		h.Difficulty = make([]byte, 0, len(buf[436:468]))
	}
	h.Difficulty = append(h.Difficulty, buf[436:468]...)

	// Field (8) 'BlockNumber'
	h.BlockNumber = ssz.UnmarshallUint64(buf[468:476])

	// Field (9) 'GasLimit'
	h.GasLimit = ssz.UnmarshallUint64(buf[476:484])

	// Field (10) 'GasUsed'
	h.GasUsed = ssz.UnmarshallUint64(buf[484:492])

	// Field (11) 'Timestamp'
	h.Timestamp = ssz.UnmarshallUint64(buf[492:500])

	// Offset (12) 'ExtraData'
	if o12 = ssz.ReadOffset(buf[500:504]); o12 > size {
		return ssz.ErrOffset
	}

	if o12 < 576 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (13) 'BaseFeePerGas'
	if cap(h.BaseFeePerGas) == 0 {
		h.BaseFeePerGas = make([]byte, 0, len(buf[504:536]))
	}
	h.BaseFeePerGas = append(h.BaseFeePerGas, buf[504:536]...)

	// Field (14) 'MixDigest'
	if cap(h.MixDigest) == 0 {
		h.MixDigest = make([]byte, 0, len(buf[536:568]))
	}
	h.MixDigest = append(h.MixDigest, buf[536:568]...)

	// Field (15) 'Nonce'
	if cap(h.Nonce) == 0 {
		h.Nonce = make([]byte, 0, len(buf[568:576]))
	}
	h.Nonce = append(h.Nonce, buf[568:576]...)

	// Field (12) 'ExtraData'
	{
		buf = tail[o12:]
		if len(buf) > 32 {
			return ssz.ErrBytesLength
		}
		if cap(h.ExtraData) == 0 {
			h.ExtraData = make([]byte, 0, len(buf))
		}
		h.ExtraData = append(h.ExtraData, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Header object
func (h *Header) SizeSSZ() (size int) {
	size = 576

	// Field (12) 'ExtraData'
	size += len(h.ExtraData)

	return
}

// HashTreeRoot ssz hashes the Header object
func (h *Header) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(h)
}

// HashTreeRootWith ssz hashes the Header object with a hasher
func (h *Header) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'ParentHash'
	if size := len(h.ParentHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.ParentHash", size, 32)
		return
	}
	hh.PutBytes(h.ParentHash)

	// Field (1) 'UncleHash'
	if size := len(h.UncleHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.UncleHash", size, 32)
		return
	}
	hh.PutBytes(h.UncleHash)

	// Field (2) 'FeeRecipient'
	if size := len(h.FeeRecipient); size != 20 {
		err = ssz.ErrBytesLengthFn("Header.FeeRecipient", size, 20)
		return
	}
	hh.PutBytes(h.FeeRecipient)

	// Field (3) 'StateRoot'
	if size := len(h.StateRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.StateRoot", size, 32)
		return
	}
	hh.PutBytes(h.StateRoot)

	// Field (4) 'TxHash'
	if size := len(h.TxHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.TxHash", size, 32)
		return
	}
	hh.PutBytes(h.TxHash)

	// Field (5) 'ReceiptsRoot'
	if size := len(h.ReceiptsRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.ReceiptsRoot", size, 32)
		return
	}
	hh.PutBytes(h.ReceiptsRoot)

	// Field (6) 'LogsBloom'
	if size := len(h.LogsBloom); size != 256 {
		err = ssz.ErrBytesLengthFn("Header.LogsBloom", size, 256)
		return
	}
	hh.PutBytes(h.LogsBloom)

	// Field (7) 'Difficulty'
	if size := len(h.Difficulty); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.Difficulty", size, 32)
		return
	}
	hh.PutBytes(h.Difficulty)

	// Field (8) 'BlockNumber'
	hh.PutUint64(h.BlockNumber)

	// Field (9) 'GasLimit'
	hh.PutUint64(h.GasLimit)

	// Field (10) 'GasUsed'
	hh.PutUint64(h.GasUsed)

	// Field (11) 'Timestamp'
	hh.PutUint64(h.Timestamp)

	// Field (12) 'ExtraData'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(h.ExtraData))
		if byteLen > 32 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.PutBytes(h.ExtraData)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32+31)/32)
	}

	// Field (13) 'BaseFeePerGas'
	if size := len(h.BaseFeePerGas); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.BaseFeePerGas", size, 32)
		return
	}
	hh.PutBytes(h.BaseFeePerGas)

	// Field (14) 'MixDigest'
	if size := len(h.MixDigest); size != 32 {
		err = ssz.ErrBytesLengthFn("Header.MixDigest", size, 32)
		return
	}
	hh.PutBytes(h.MixDigest)

	// Field (15) 'Nonce'
	if size := len(h.Nonce); size != 8 {
		err = ssz.ErrBytesLengthFn("Header.Nonce", size, 8)
		return
	}
	hh.PutBytes(h.Nonce)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Header object
func (h *Header) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(h)
}

// MarshalSSZ ssz marshals the Receipt object
func (r *Receipt) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(r)
}

// MarshalSSZTo ssz marshals the Receipt object to a target array
func (r *Receipt) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(24)

	// Offset (0) 'PostState'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(r.PostState)

	// Field (1) 'Status'
	dst = ssz.MarshalUint64(dst, r.Status)

	// Field (2) 'CumulativeGasUsed'
	dst = ssz.MarshalUint64(dst, r.CumulativeGasUsed)

	// Offset (3) 'Logs'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(r.Logs); ii++ {
		offset += 4
		offset += r.Logs[ii].SizeSSZ()
	}

	// Field (0) 'PostState'
	if size := len(r.PostState); size > 32 {
		err = ssz.ErrBytesLengthFn("Receipt.PostState", size, 32)
		return
	}
	dst = append(dst, r.PostState...)

	// Field (3) 'Logs'
	if size := len(r.Logs); size > 4194452 {
		err = ssz.ErrListTooBigFn("Receipt.Logs", size, 4194452)
		return
	}
	{
		offset = 4 * len(r.Logs)
		for ii := 0; ii < len(r.Logs); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += r.Logs[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(r.Logs); ii++ {
		if dst, err = r.Logs[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the Receipt object
func (r *Receipt) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 24 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o3 uint64

	// Offset (0) 'PostState'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 24 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Status'
	r.Status = ssz.UnmarshallUint64(buf[4:12])

	// Field (2) 'CumulativeGasUsed'
	r.CumulativeGasUsed = ssz.UnmarshallUint64(buf[12:20])

	// Offset (3) 'Logs'
	if o3 = ssz.ReadOffset(buf[20:24]); o3 > size || o0 > o3 {
		return ssz.ErrOffset
	}

	// Field (0) 'PostState'
	{
		buf = tail[o0:o3]
		if len(buf) > 32 {
			return ssz.ErrBytesLength
		}
		if cap(r.PostState) == 0 {
			r.PostState = make([]byte, 0, len(buf))
		}
		r.PostState = append(r.PostState, buf...)
	}

	// Field (3) 'Logs'
	{
		buf = tail[o3:]
		num, err := ssz.DecodeDynamicLength(buf, 4194452)
		if err != nil {
			return err
		}
		r.Logs = make([]*Log, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if r.Logs[indx] == nil {
				r.Logs[indx] = new(Log)
			}
			if err = r.Logs[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Receipt object
func (r *Receipt) SizeSSZ() (size int) {
	size = 24

	// Field (0) 'PostState'
	size += len(r.PostState)

	// Field (3) 'Logs'
	for ii := 0; ii < len(r.Logs); ii++ {
		size += 4
		size += r.Logs[ii].SizeSSZ()
	}

	return
}

// HashTreeRoot ssz hashes the Receipt object
func (r *Receipt) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(r)
}

// HashTreeRootWith ssz hashes the Receipt object with a hasher
func (r *Receipt) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'PostState'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(r.PostState))
		if byteLen > 32 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.PutBytes(r.PostState)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32+31)/32)
	}

	// Field (1) 'Status'
	hh.PutUint64(r.Status)

	// Field (2) 'CumulativeGasUsed'
	hh.PutUint64(r.CumulativeGasUsed)

	// Field (3) 'Logs'
	{
		subIndx := hh.Index()
		num := uint64(len(r.Logs))
		if num > 4194452 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range r.Logs {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 4194452)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Receipt object
func (r *Receipt) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(r)
}

// MarshalSSZ ssz marshals the Log object
func (l *Log) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(l)
}

// MarshalSSZTo ssz marshals the Log object to a target array
func (l *Log) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(28)

	// Field (0) 'Address'
	if size := len(l.Address); size != 20 {
		err = ssz.ErrBytesLengthFn("Log.Address", size, 20)
		return
	}
	dst = append(dst, l.Address...)

	// Offset (1) 'Topics'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(l.Topics) * 32

	// Offset (2) 'Data'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(l.Data)

	// Field (1) 'Topics'
	if size := len(l.Topics); size > 4 {
		err = ssz.ErrListTooBigFn("Log.Topics", size, 4)
		return
	}
	for ii := 0; ii < len(l.Topics); ii++ {
		if size := len(l.Topics[ii]); size != 32 {
			err = ssz.ErrBytesLengthFn("Log.Topics[ii]", size, 32)
			return
		}
		dst = append(dst, l.Topics[ii]...)
	}

	// Field (2) 'Data'
	if size := len(l.Data); size > 4194304 {
		err = ssz.ErrBytesLengthFn("Log.Data", size, 4194304)
		return
	}
	dst = append(dst, l.Data...)

	return
}

// UnmarshalSSZ ssz unmarshals the Log object
func (l *Log) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 28 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2 uint64

	// Field (0) 'Address'
	if cap(l.Address) == 0 {
		l.Address = make([]byte, 0, len(buf[0:20]))
	}
	l.Address = append(l.Address, buf[0:20]...)

	// Offset (1) 'Topics'
	if o1 = ssz.ReadOffset(buf[20:24]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 28 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'Data'
	if o2 = ssz.ReadOffset(buf[24:28]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (1) 'Topics'
	{
		buf = tail[o1:o2]
		num, err := ssz.DivideInt2(len(buf), 32, 4)
		if err != nil {
			return err
		}
		l.Topics = make([][]byte, num)
		for ii := 0; ii < num; ii++ {
			if cap(l.Topics[ii]) == 0 {
				l.Topics[ii] = make([]byte, 0, len(buf[ii*32:(ii+1)*32]))
			}
			l.Topics[ii] = append(l.Topics[ii], buf[ii*32:(ii+1)*32]...)
		}
	}

	// Field (2) 'Data'
	{
		buf = tail[o2:]
		if len(buf) > 4194304 {
			return ssz.ErrBytesLength
		}
		if cap(l.Data) == 0 {
			l.Data = make([]byte, 0, len(buf))
		}
		l.Data = append(l.Data, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Log object
func (l *Log) SizeSSZ() (size int) {
	size = 28

	// Field (1) 'Topics'
	size += len(l.Topics) * 32

	// Field (2) 'Data'
	size += len(l.Data)

	return
}

// HashTreeRoot ssz hashes the Log object
func (l *Log) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(l)
}

// HashTreeRootWith ssz hashes the Log object with a hasher
func (l *Log) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Address'
	if size := len(l.Address); size != 20 {
		err = ssz.ErrBytesLengthFn("Log.Address", size, 20)
		return
	}
	hh.PutBytes(l.Address)

	// Field (1) 'Topics'
	{
		if size := len(l.Topics); size > 4 {
			err = ssz.ErrListTooBigFn("Log.Topics", size, 4)
			return
		}
		subIndx := hh.Index()
		for _, i := range l.Topics {
			if len(i) != 32 {
				err = ssz.ErrBytesLength
				return
			}
			hh.Append(i)
		}
		numItems := uint64(len(l.Topics))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(4, numItems, 32))
	}

	// Field (2) 'Data'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(l.Data))
		if byteLen > 4194304 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.PutBytes(l.Data)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (4194304+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Log object
func (l *Log) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(l)
}
