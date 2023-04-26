package era

// func (r *Reader) Verify() error {
//         var (
//                 err    error
//                 want   common.Hash
//                 td     *big.Int
//                 tds    = make([]*big.Int, 0)
//                 hashes = make([]common.Hash, 0)
//         )
//         if want, err = r.Accumulator(); err != nil {
//                 return fmt.Errorf("error reading accumulator: %w", err)
//         }
//         if td, err = r.TotalDifficulty(); err != nil {
//                 return fmt.Errorf("error reading total difficulty: %w", err)
//         }

//         start, err := r.Start()
//         if err != nil {
//                 return fmt.Errorf("error reading start offset: %w", err)
//         }
//         // Save current block offset and replace after verifying.
//         if r.offset != nil {
//                 saved := *r.offset
//                 r.offset = &start
//                 defer func() {
//                         r.offset = &saved
//                 }()
//         }
//         // Accumulate block hash and total difficulty values.
//         for block, receipts, err := r.Read(); ; block, receipts, err = r.Read() {
//                 if err == io.EOF {
//                         break
//                 } else if err != nil {
//                         return fmt.Errorf("error reading era1: %w", err)
//                 }
//                 // Verify ommer hash.
//                 ur := types.CalcUncleHash(block.Uncles())
//                 if ur != block.UncleHash() {
//                         return fmt.Errorf("tx root in block %d mismatch: want %s, got %s", block.NumberU64(), block.UncleHash(), ur)
//                 }
//                 // Verify tx hash.
//                 tr := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil))
//                 if tr != block.TxHash() {
//                         return fmt.Errorf("tx root in block %d mismatch: want %s, got %s", block.NumberU64(), block.TxHash(), tr)
//                 }
//                 // Verify receipt root.
//                 rr := types.DeriveSha(receipts, trie.NewStackTrie(nil))
//                 if rr != block.ReceiptHash() {
//                         return fmt.Errorf("receipt root in block %d mismatch: want %s, got %s", block.NumberU64(), block.ReceiptHash(), rr)
//                 }
//                 hashes = append(hashes, block.Hash())
//                 td.Add(td, block.Difficulty())
//                 tds = append(tds, new(big.Int).Set(td))
//         }
//         got, err := ComputeAccumulator(hashes, tds)
//         if err != nil {
//                 return fmt.Errorf("error computing accumulator: %w", err)
//         }
//         if got != want {
//                 return fmt.Errorf("expected accumulator root does not match calculated: got %s, want %s", got, want)
//         }
//         return nil
// }
