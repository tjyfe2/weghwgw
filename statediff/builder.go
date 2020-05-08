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
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

var nullNode = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")

// Builder interface exposes the method for building a state diff between two blocks
type Builder interface {
	BuildStateDiff(oldStateRoot, newStateRoot common.Hash, blockNumber *big.Int, blockHash common.Hash) (StateDiff, error)
}

type builder struct {
	config     Config
	blockChain *core.BlockChain
	stateCache state.Database
}

// NewBuilder is used to create a statediff builder
func NewBuilder(blockChain *core.BlockChain, config Config) Builder {
	return &builder{
		config:     config,
		blockChain: blockChain,
	}
}

// BuildStateDiff builds a statediff object from two blocks
func (sdb *builder) BuildStateDiff(oldStateRoot, newStateRoot common.Hash, blockNumber *big.Int, blockHash common.Hash) (StateDiff, error) {
	// Generate tries for old and new states
	sdb.stateCache = sdb.blockChain.StateCache()
	oldTrie, err := sdb.stateCache.OpenTrie(oldStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for oldStateRoot: %v", err)
	}
	newTrie, err := sdb.stateCache.OpenTrie(newStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for newStateRoot: %v", err)
	}

	// Find created accounts
	creations, err := sdb.collectDiffNodes(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}))
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting creation diff nodes: %v", err)
	}

	// Find deleted accounts
	deletions, err := sdb.collectDiffNodes(newTrie.NodeIterator([]byte{}), oldTrie.NodeIterator([]byte{}))
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting deletion diff nodes: %v", err)
	}

	// Find all the diffed keys
	createKeys := sortKeys(creations)
	deleteKeys := sortKeys(deletions)
	updatedKeys := findIntersection(createKeys, deleteKeys)

	// Build and return the statediff
	updatedAccounts, err := sdb.buildDiffIncremental(creations, deletions, updatedKeys)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for updated accounts: %v", err)
	}
	createdAccounts, err := sdb.buildDiffEventual(creations)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for created accounts: %v", err)
	}
	deletedAccounts, err := sdb.buildDiffEventual(deletions)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for deleted accounts: %v", err)
	}

	return StateDiff{
		BlockNumber:     blockNumber,
		BlockHash:       blockHash,
		CreatedAccounts: createdAccounts,
		DeletedAccounts: deletedAccounts,
		UpdatedAccounts: updatedAccounts,
	}, nil
}

// isWatchedAddress is used to check if a state account corresponds to one of the addresses the builder is configured to watch
func (sdb *builder) isWatchedAddress(hashKey []byte) bool {
	// If we aren't watching any specific addresses, we are watching everything
	if len(sdb.config.WatchedAddresses) == 0 {
		return true
	}
	for _, addrStr := range sdb.config.WatchedAddresses {
		addr := common.HexToAddress(addrStr)
		addrHashKey := crypto.Keccak256(addr[:])
		if bytes.Equal(addrHashKey, hashKey) {
			return true
		}
	}
	return false
}

func (sdb *builder) collectDiffNodes(a, b trie.NodeIterator) (AccountsMap, error) {
	diffAccounts := make(AccountsMap)
	it, _ := trie.NewDifferenceIterator(a, b)
	for it.Next(true) {
		// skip value nodes
		if it.Leaf() {
			continue
		}
		if bytes.Equal(nullNode, it.Hash().Bytes()) {
			continue
		}
		nodePath := make([]byte, len(it.Path()))
		copy(nodePath, it.Path())
		node, err := sdb.stateCache.TrieDB().Node(it.Hash())
		if err != nil {
			return nil, err
		}
		var nodeElements []interface{}
		if err := rlp.DecodeBytes(node, &nodeElements); err != nil {
			return nil, err
		}
		ty, err := CheckKeyType(nodeElements)
		if err != nil {
			return nil, err
		}
		nodePathHash := crypto.Keccak256Hash(nodePath)
		switch ty {
		case Leaf:
			var account state.Account
			if err := rlp.DecodeBytes(nodeElements[1].([]byte), &account); err != nil {
				return nil, fmt.Errorf("error decoding account for leaf node at path %x nerror: %v", nodePath, err)
			}
			partialPath := trie.CompactToHex(nodeElements[0].([]byte))
			valueNodePath := append(nodePath, partialPath...)
			encodedPath := trie.HexToCompact(valueNodePath)
			leafKey := encodedPath[1:]
			if sdb.isWatchedAddress(leafKey) {
				aw := accountWrapper{
					NodeType:  ty,
					Path:      nodePath,
					NodeValue: node,
					LeafKey:   leafKey,
					Account:   &account,
				}
				diffAccounts[nodePathHash] = aw
			}
		case Extension, Branch:
			if sdb.config.IntermediateNodes {
				diffAccounts[nodePathHash] = accountWrapper{
					NodeType:  ty,
					Path:      nodePath,
					NodeValue: node,
				}
			}
		default:
			return nil, fmt.Errorf("unexpected node type %s", ty)
		}
	}
	return diffAccounts, nil
}

func (sdb *builder) buildDiffEventual(accounts AccountsMap) ([]AccountDiff, error) {
	accountDiffs := make([]AccountDiff, 0)
	var err error
	for _, val := range accounts {
		// If account is not nil, we need to process storage diffs
		var storageDiffs []StorageDiff
		if val.Account != nil {
			storageDiffs, err = sdb.buildStorageDiffsEventual(val.Account.Root)
			if err != nil {
				return nil, fmt.Errorf("failed building eventual storage diffs for node %x\r\nerror: %v", val.Path, err)
			}
		}
		accountDiffs = append(accountDiffs, AccountDiff{
			NodeType:  val.NodeType,
			Path:      val.Path,
			LeafKey:   val.LeafKey,
			NodeValue: val.NodeValue,
			Storage:   storageDiffs,
		})
	}

	return accountDiffs, nil
}

func (sdb *builder) buildDiffIncremental(creations AccountsMap, deletions AccountsMap, updatedKeys []string) ([]AccountDiff, error) {
	updatedAccounts := make([]AccountDiff, 0)
	var err error
	for _, val := range updatedKeys {
		hashKey := common.HexToHash(val)
		createdAcc := creations[hashKey]
		deletedAcc := deletions[hashKey]
		var storageDiffs []StorageDiff
		if deletedAcc.Account != nil && createdAcc.Account != nil {
			oldSR := deletedAcc.Account.Root
			newSR := createdAcc.Account.Root
			storageDiffs, err = sdb.buildStorageDiffsIncremental(oldSR, newSR)
			if err != nil {
				return nil, fmt.Errorf("failed building incremental storage diffs for %s\r\nerror: %v", hashKey.Hex(), err)
			}
		}
		updatedAccounts = append(updatedAccounts, AccountDiff{
			NodeType:  createdAcc.NodeType,
			Path:      createdAcc.Path,
			NodeValue: createdAcc.NodeValue,
			LeafKey:   createdAcc.LeafKey,
			Storage:   storageDiffs,
		})
		delete(creations, common.HexToHash(val))
		delete(deletions, common.HexToHash(val))
	}

	return updatedAccounts, nil
}

func (sdb *builder) buildStorageDiffsEventual(sr common.Hash) ([]StorageDiff, error) {
	log.Debug("Storage Root For Eventual Diff", "root", sr.Hex())
	stateCache := sdb.blockChain.StateCache()
	sTrie, err := stateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build storage diff eventual", "error", err)
		return nil, err
	}
	it := sTrie.NodeIterator(make([]byte, 0))
	return sdb.buildStorageDiffsFromTrie(it)
}

func (sdb *builder) buildStorageDiffsIncremental(oldSR common.Hash, newSR common.Hash) ([]StorageDiff, error) {
	log.Debug("Storage Roots for Incremental Diff", "old", oldSR.Hex(), "new", newSR.Hex())
	stateCache := sdb.blockChain.StateCache()

	oldTrie, err := stateCache.OpenTrie(oldSR)
	if err != nil {
		return nil, err
	}
	newTrie, err := stateCache.OpenTrie(newSR)
	if err != nil {
		return nil, err
	}

	oldIt := oldTrie.NodeIterator(make([]byte, 0))
	newIt := newTrie.NodeIterator(make([]byte, 0))
	it, _ := trie.NewDifferenceIterator(oldIt, newIt)
	return sdb.buildStorageDiffsFromTrie(it)
}

func (sdb *builder) buildStorageDiffsFromTrie(it trie.NodeIterator) ([]StorageDiff, error) {
	storageDiffs := make([]StorageDiff, 0)
	for it.Next(true) {
		// skip value nodes
		if it.Leaf() {
			continue
		}
		if bytes.Equal(nullNode, it.Hash().Bytes()) {
			continue
		}
		nodePath := make([]byte, len(it.Path()))
		copy(nodePath, it.Path())
		node, err := sdb.stateCache.TrieDB().Node(it.Hash())
		if err != nil {
			return nil, err
		}
		var nodeElements []interface{}
		if err := rlp.DecodeBytes(node, &nodeElements); err != nil {
			return nil, err
		}
		ty, err := CheckKeyType(nodeElements)
		if err != nil {
			return nil, err
		}
		switch ty {
		case Leaf:
			partialPath := trie.CompactToHex(nodeElements[0].([]byte))
			valueNodePath := append(nodePath, partialPath...)
			encodedPath := trie.HexToCompact(valueNodePath)
			leafKey := encodedPath[1:]
			sd := StorageDiff{
				NodeType:  ty,
				Path:      nodePath,
				NodeValue: node,
				LeafKey:   leafKey,
			}
			storageDiffs = append(storageDiffs, sd)
		case Extension, Branch:
			if sdb.config.IntermediateNodes {
				storageDiffs = append(storageDiffs, StorageDiff{
					NodeType:  ty,
					Path:      nodePath,
					NodeValue: node,
				})
			}
		default:
			return nil, fmt.Errorf("unexpected node type %s", ty)
		}
	}
	return storageDiffs, nil
}
