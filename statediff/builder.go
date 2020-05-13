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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

var nullNode = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")

// Builder interface exposes the method for building a state diff between two blocks
type Builder interface {
	BuildStateDiff(args Args, params Params) (StateDiff, error)
}

type builder struct {
	stateCache state.Database
}

// NewBuilder is used to create a statediff builder
func NewBuilder(stateCache state.Database) Builder {
	return &builder{
		stateCache: stateCache, // state cache is safe for concurrent reads
	}
}

// BuildStateDiff builds a statediff object from two blocks and the provided parameters
func (sdb *builder) BuildStateDiff(args Args, params Params) (StateDiff, error) {
	if !params.IntermediateStateNodes || len(params.WatchedAddresses) > 0 { // if we are watching only specific accounts then we are only diffing leaf nodes
		return sdb.buildStateDiffWithoutIntermediateStateNodes(args, params)
	}
	return sdb.buildStateDiffWithIntermediateStateNodes(args, params.IntermediateStorageNodes)
}

func (sdb *builder) buildStateDiffWithIntermediateStateNodes(args Args, intermediateStorageNodes bool) (StateDiff, error) {
	// Generate tries for old and new states
	oldTrie, err := sdb.stateCache.OpenTrie(args.OldStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for oldStateRoot: %v", err)
	}
	newTrie, err := sdb.stateCache.OpenTrie(args.NewStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for newStateRoot: %v", err)
	}

	createdOrUpdatedIntermediateNodes, diffAccountsAtB, diffPathsAtB, err := sdb.createdAndUpdatedNodes(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}))
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting createdAndUpdatedNodes: %v", err)
	}

	deletedIntermediateNodes, diffAccountsAtA, err := sdb.deletedOrUpdatedNodes(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}), diffPathsAtB)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting deletedOrUpdatedNodes: %v", err)
	}

	// Find all the diffed keys
	createKeys := sortKeys(diffAccountsAtB)
	deleteKeys := sortKeys(diffAccountsAtA)
	updatedKeys := findIntersection(createKeys, deleteKeys)

	// Build and return the statediff
	updatedAccounts, err := sdb.buildAccountUpdates(diffAccountsAtB, diffAccountsAtA, updatedKeys, intermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for updated accounts: %v", err)
	}
	createdAccounts, err := sdb.buildAccountCreations(diffAccountsAtB, intermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for created accounts: %v", err)
	}
	deletedAccounts, err := sdb.buildAccountDeletions(diffAccountsAtA)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for deleted accounts: %v", err)
	}

	return StateDiff{
		BlockNumber: args.BlockNumber,
		BlockHash:   args.BlockHash,
		Nodes:       append(append(append(append(updatedAccounts, createdAccounts...), deletedAccounts...), createdOrUpdatedIntermediateNodes...), deletedIntermediateNodes...),
	}, nil
}

func (sdb *builder) buildStateDiffWithoutIntermediateStateNodes(args Args, params Params) (StateDiff, error) {
	// Generate tries for old and new states
	oldTrie, err := sdb.stateCache.OpenTrie(args.OldStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for oldStateRoot: %v", err)
	}
	newTrie, err := sdb.stateCache.OpenTrie(args.NewStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for newStateRoot: %v", err)
	}

	diffAccountsAtB, err := sdb.collectDiffAccounts(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}), params.WatchedAddresses)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting createdAndUpdatedNodes: %v", err)
	}

	diffAccountsAtA, err := sdb.collectDiffAccounts(newTrie.NodeIterator([]byte{}), oldTrie.NodeIterator([]byte{}), params.WatchedAddresses)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting deletedOrUpdatedNodes: %v", err)
	}

	// Find all the diffed keys
	createKeys := sortKeys(diffAccountsAtB)
	deleteKeys := sortKeys(diffAccountsAtA)
	updatedKeys := findIntersection(createKeys, deleteKeys)

	// Build and return the statediff
	updatedAccounts, err := sdb.buildAccountUpdates(diffAccountsAtB, diffAccountsAtA, updatedKeys, params.IntermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for updated accounts: %v", err)
	}
	createdAccounts, err := sdb.buildAccountCreations(diffAccountsAtB, params.IntermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for created accounts: %v", err)
	}
	deletedAccounts, err := sdb.buildAccountDeletions(diffAccountsAtA)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for deleted accounts: %v", err)
	}

	return StateDiff{
		BlockNumber: args.BlockNumber,
		BlockHash:   args.BlockHash,
		Nodes:       append(append(updatedAccounts, createdAccounts...), deletedAccounts...),
	}, nil
}

func (sdb *builder) collectDiffAccounts(a, b trie.NodeIterator, watchedAddresses []string) (AccountMap, error) {
	diffAcountsAtB := make(AccountMap)
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
		switch ty {
		case Leaf:
			// created vs updated is important for leaf nodes since we need to diff their storage
			// so we need to map all changed accounts at B to their leafkey, since account can change pathes but not leafkey
			var account state.Account
			if err := rlp.DecodeBytes(nodeElements[1].([]byte), &account); err != nil {
				return nil, fmt.Errorf("error decoding account for leaf node at path %x nerror: %v", nodePath, err)
			}
			partialPath := trie.CompactToHex(nodeElements[0].([]byte))
			valueNodePath := append(nodePath, partialPath...)
			encodedPath := trie.HexToCompact(valueNodePath)
			leafKey := encodedPath[1:]
			if isWatchedAddress(watchedAddresses, leafKey) {
				diffAcountsAtB[common.Bytes2Hex(leafKey)] = accountWrapper{
					NodeType:  ty,
					Path:      nodePath,
					NodeValue: node,
					LeafKey:   leafKey,
					Account:   &account,
				}
			}
		case Extension, Branch:
			// fall through to next iteration
		default:
			return nil, fmt.Errorf("unexpected node type %s", ty)
		}
	}
	return diffAcountsAtB, nil
}

// isWatchedAddress is used to check if a state account corresponds to one of the addresses the builder is configured to watch
func isWatchedAddress(watchedAddresses []string, hashKey []byte) bool {
	// If we aren't watching any specific addresses, we are watching everything
	if len(watchedAddresses) == 0 {
		return true
	}
	for _, addrStr := range watchedAddresses {
		addr := common.HexToAddress(addrStr)
		addrHashKey := crypto.Keccak256(addr[:])
		if bytes.Equal(addrHashKey, hashKey) {
			return true
		}
	}
	return false
}

// createdAndUpdatedNodes returns a slice of all the intermediate nodes that are different in b than they are in a
// it also returns a map of LEAFKEY to all the leaf nodes (accounts) that are different in b than they are in a
// it also returns a list of the intermediate node paths that were touched and the leaf node PATHs that were touched
// this function should only be called b = the NodeIterator for the state trie at  a.blockheight + 1
// make version for leaf nodes only
func (sdb *builder) createdAndUpdatedNodes(a, b trie.NodeIterator) ([]StateNode, AccountMap, map[string]bool, error) {
	createdOrUpdatedIntermediateNodes := make([]StateNode, 0)
	diffPathsAtB := make(map[string]bool)
	diffAcountsAtB := make(AccountMap)
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
			return nil, nil, nil, err
		}
		var nodeElements []interface{}
		if err := rlp.DecodeBytes(node, &nodeElements); err != nil {
			return nil, nil, nil, err
		}
		ty, err := CheckKeyType(nodeElements)
		if err != nil {
			return nil, nil, nil, err
		}
		switch ty {
		case Leaf:
			// created vs updated is important for leaf nodes since we need to diff their storage
			// so we need to map all changed accounts at B to their leafkey, since account can change pathes but not leafkey
			var account state.Account
			if err := rlp.DecodeBytes(nodeElements[1].([]byte), &account); err != nil {
				return nil, nil, nil, fmt.Errorf("error decoding account for leaf node at path %x nerror: %v", nodePath, err)
			}
			partialPath := trie.CompactToHex(nodeElements[0].([]byte))
			valueNodePath := append(nodePath, partialPath...)
			encodedPath := trie.HexToCompact(valueNodePath)
			leafKey := encodedPath[1:]
			diffAcountsAtB[common.Bytes2Hex(leafKey)] = accountWrapper{
				NodeType:  ty,
				Path:      nodePath,
				NodeValue: node,
				LeafKey:   leafKey,
				Account:   &account,
			}
		case Extension, Branch:
			// create a diff for any intermediate node that has changed at b
			// created vs updated makes no difference for intermediate nodes since we do not need to diff storage
			createdOrUpdatedIntermediateNodes = append(createdOrUpdatedIntermediateNodes, StateNode{
				NodeType:  ty,
				Path:      nodePath,
				NodeValue: node,
			})
		default:
			return nil, nil, nil, fmt.Errorf("unexpected node type %s", ty)
		}
		// add both intermediate and leaf node paths to the list of diffPathsAtB
		diffPathsAtB[common.Bytes2Hex(nodePath)] = true
	}
	return createdOrUpdatedIntermediateNodes, diffAcountsAtB, diffPathsAtB, nil
}

func (sdb *builder) deletedOrUpdatedNodes(a, b trie.NodeIterator, diffPathsAtB map[string]bool) ([]StateNode, AccountMap, error) {
	deletedIntermediateNodes := make([]StateNode, 0)
	diffAccountAtA := make(AccountMap)
	it, _ := trie.NewDifferenceIterator(b, a)
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
			return nil, nil, err
		}
		var nodeElements []interface{}
		if err := rlp.DecodeBytes(node, &nodeElements); err != nil {
			return nil, nil, err
		}
		ty, err := CheckKeyType(nodeElements)
		if err != nil {
			return nil, nil, err
		}
		switch ty {
		case Leaf:
			// map all different accounts at A to their leafkey
			var account state.Account
			if err := rlp.DecodeBytes(nodeElements[1].([]byte), &account); err != nil {
				return nil, nil, fmt.Errorf("error decoding account for leaf node at path %x nerror: %v", nodePath, err)
			}
			partialPath := trie.CompactToHex(nodeElements[0].([]byte))
			valueNodePath := append(nodePath, partialPath...)
			encodedPath := trie.HexToCompact(valueNodePath)
			leafKey := encodedPath[1:]
			diffAccountAtA[common.Bytes2Hex(leafKey)] = accountWrapper{
				NodeType:  ty,
				Path:      nodePath,
				NodeValue: node,
				LeafKey:   leafKey,
				Account:   &account,
			}
		case Extension, Branch:
			// if this nodePath did not show up in diffPathsAtB
			// that means the node at this path at A was deleted in B
			if _, ok := diffPathsAtB[common.Bytes2Hex(nodePath)]; !ok {
				deletedIntermediateNodes = append(deletedIntermediateNodes, StateNode{
					NodeType:  Removed,
					Path:      nodePath,
					NodeValue: []byte{},
				})
			}
		default:
			return nil, nil, fmt.Errorf("unexpected node type %s", ty)
		}
	}
	return deletedIntermediateNodes, diffAccountAtA, nil
}

// needs to be called before building account creations and deletions as this mutattes
// those account maps to remove the accounts which were updated
func (sdb *builder) buildAccountUpdates(creations, deletions AccountMap, updatedKeys []string, intermediateStorageNodes bool) ([]StateNode, error) {
	updatedAccounts := make([]StateNode, 0, len(updatedKeys))
	var err error
	for _, key := range updatedKeys {
		createdAcc := creations[key]
		deletedAcc := deletions[key]
		var storageDiffs []StorageNode
		if deletedAcc.Account != nil && createdAcc.Account != nil {
			oldSR := deletedAcc.Account.Root
			newSR := createdAcc.Account.Root
			storageDiffs, err = sdb.buildStorageNodesIncremental(oldSR, newSR, intermediateStorageNodes)
			if err != nil {
				return nil, fmt.Errorf("failed building incremental storage diffs for account with leafkey %s\r\nerror: %v", key, err)
			}
		}
		updatedAccounts = append(updatedAccounts, StateNode{
			NodeType:     createdAcc.NodeType,
			Path:         createdAcc.Path,
			NodeValue:    createdAcc.NodeValue,
			LeafKey:      createdAcc.LeafKey,
			StorageDiffs: storageDiffs,
		})
		delete(creations, key)
		delete(deletions, key)
	}

	return updatedAccounts, nil
}

func (sdb *builder) buildAccountCreations(accounts AccountMap, intermediateStorageNodes bool) ([]StateNode, error) {
	accountDiffs := make([]StateNode, 0, len(accounts))
	for _, val := range accounts {
		// For account creations, any storage node contained is a diff
		storageDiffs, err := sdb.buildStorageNodesEventual(val.Account.Root, intermediateStorageNodes)
		if err != nil {
			return nil, fmt.Errorf("failed building eventual storage diffs for node %x\r\nerror: %v", val.Path, err)
		}
		accountDiffs = append(accountDiffs, StateNode{
			NodeType:     val.NodeType,
			Path:         val.Path,
			LeafKey:      val.LeafKey,
			NodeValue:    val.NodeValue,
			StorageDiffs: storageDiffs,
		})
	}

	return accountDiffs, nil
}

func (sdb *builder) buildAccountDeletions(accounts AccountMap) ([]StateNode, error) {
	accountDiffs := make([]StateNode, 0, len(accounts))
	for _, val := range accounts {
		// For account deletions, we can not have any storage or the account would not be deleted
		accountDiffs = append(accountDiffs, StateNode{
			NodeType:  Removed,
			Path:      val.Path,
			LeafKey:   val.LeafKey,
			NodeValue: []byte{},
		})
	}
	return accountDiffs, nil
}

func (sdb *builder) buildStorageNodesEventual(sr common.Hash, intermediateNodes bool) ([]StorageNode, error) {
	log.Debug("Storage Root For Eventual Diff", "root", sr.Hex())
	sTrie, err := sdb.stateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build storage diff eventual", "error", err)
		return nil, err
	}
	it := sTrie.NodeIterator(make([]byte, 0))
	return sdb.buildStorageNodesFromTrie(it, intermediateNodes)
}

func (sdb *builder) buildStorageNodesIncremental(oldSR common.Hash, newSR common.Hash, intermediateNodes bool) ([]StorageNode, error) {
	log.Debug("Storage Roots for Incremental Diff", "old", oldSR.Hex(), "new", newSR.Hex())
	oldTrie, err := sdb.stateCache.OpenTrie(oldSR)
	if err != nil {
		return nil, err
	}
	newTrie, err := sdb.stateCache.OpenTrie(newSR)
	if err != nil {
		return nil, err
	}

	oldIt := oldTrie.NodeIterator(make([]byte, 0))
	newIt := newTrie.NodeIterator(make([]byte, 0))
	it, _ := trie.NewDifferenceIterator(oldIt, newIt)
	return sdb.buildStorageNodesFromTrie(it, intermediateNodes)
}

func (sdb *builder) buildStorageNodesFromTrie(it trie.NodeIterator, intermediateNodes bool) ([]StorageNode, error) {
	storageDiffs := make([]StorageNode, 0)
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
			storageDiffs = append(storageDiffs, StorageNode{
				NodeType:  ty,
				Path:      nodePath,
				NodeValue: node,
				LeafKey:   leafKey,
			})
		case Extension, Branch:
			if intermediateNodes {
				storageDiffs = append(storageDiffs, StorageNode{
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
