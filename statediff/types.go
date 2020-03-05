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

// Contains a batch of utility type declarations used by the tests. As the node
// operates on unique types, a lot of them are needed to check various features.

package statediff

import (
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/core/state"

	"github.com/ethereum/go-ethereum/common"
)

// Subscription struct holds our subscription channels
type Subscription struct {
	PayloadChan chan<- Payload
	QuitChan    chan<- bool
}

// Payload packages the data to send to statediff subscriptions
type Payload struct {
	BlockRlp        []byte   `json:"blockRlp"`
	TotalDifficulty *big.Int `json:"totalDifficulty"`
	ReceiptsRlp     []byte   `json:"receiptsRlp"`
	StateDiffRlp    []byte   `json:"stateDiff"    gencodec:"required"`

	encoded []byte
	err     error
}

func (sd *Payload) ensureEncoded() {
	if sd.encoded == nil && sd.err == nil {
		sd.encoded, sd.err = json.Marshal(sd)
	}
}

// Length to implement Encoder interface for Payload
func (sd *Payload) Length() int {
	sd.ensureEncoded()
	return len(sd.encoded)
}

// Encode to implement Encoder interface for Payload
func (sd *Payload) Encode() ([]byte, error) {
	sd.ensureEncoded()
	return sd.encoded, sd.err
}

// StateDiff is the final output structure from the builder
type StateDiff struct {
	BlockNumber     *big.Int      `json:"blockNumber"     gencodec:"required"`
	BlockHash       common.Hash   `json:"blockHash"       gencodec:"required"`
	CreatedAccounts []AccountDiff `json:"createdAccounts" gencodec:"required"`
	DeletedAccounts []AccountDiff `json:"deletedAccounts" gencodec:"required"`
	UpdatedAccounts []AccountDiff `json:"updatedAccounts" gencodec:"required"`

	encoded []byte
	err     error
}

// AccountDiff holds the data for a single state diff node
type AccountDiff struct {
	NodeType  NodeType      `json:"nodeType"        gencodec:"required"`
	Path      []byte        `json:"path"         gencodec:"required"`
	NodeValue []byte        `json:"value"       gencodec:"required"`
	Storage   []StorageDiff `json:"storage"`
	LeafKey   []byte        `json:"leafKey"`
}

// StorageDiff holds the data for a single storage diff node
type StorageDiff struct {
	NodeType  NodeType `json:"nodeType"        gencodec:"required"`
	Path      []byte   `json:"path"     gencodec:"required"`
	NodeValue []byte   `json:"value"       gencodec:"required"`
	LeafKey   []byte   `json:"leafKey"`
}

// AccountsMap is a mapping of keccak256(address) => accountWrapper
type AccountsMap map[common.Hash]accountWrapper

// AccountWrapper is used to temporary associate the unpacked account with its raw values
type accountWrapper struct {
	Account   *state.Account
	NodeType  NodeType
	Path      []byte
	NodeValue []byte
	LeafKey   []byte
}

// NodeType for explicitly setting type of node
type NodeType string

const (
	Unknown   NodeType = "Unknown"
	Leaf      NodeType = "Leaf"
	Extension NodeType = "Extension"
	Branch    NodeType = "Branch"
)
