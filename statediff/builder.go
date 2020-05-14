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
	return sdb.buildStateDiffWithIntermediateStateNodes(args, params)
}

func (sdb *builder) buildStateDiffWithIntermediateStateNodes(args Args, params Params) (StateDiff, error) {
	// Load tries for old and new states
	oldTrie, err := sdb.stateCache.OpenTrie(args.OldStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for oldStateRoot: %v", err)
	}
	newTrie, err := sdb.stateCache.OpenTrie(args.NewStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for newStateRoot: %v", err)
	}

	// collect a slice of all the intermediate nodes that were touched and exist at B
	// a map of their leafkey to all the accounts that were touched and exist at B
	// and a slice of all the paths for the nodes in both of the above sets
	createdOrUpdatedIntermediateNodes, diffAccountsAtB, diffPathsAtB, err := sdb.createdAndUpdatedNodes(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}))
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting createdAndUpdatedNodes: %v", err)
	}

	// collect a slice of all the intermediate nodes that existed at A but don't at B
	// a map of their leafkey to all the accounts that were touched and exist at A
	deletedIntermediateNodes, diffAccountsAtA, err := sdb.deletedOrUpdatedNodes(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}), diffPathsAtB)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting deletedOrUpdatedNodes: %v", err)
	}

	// collect and sort the leafkey keys for both account mappings into a slice
	createKeys := sortKeys(diffAccountsAtB)
	deleteKeys := sortKeys(diffAccountsAtA)

	// and then find the intersection of these keys
	// these are the leafkeys for the accounts which exist at both A and B but are different
	// this also mutates the passed in createKeys and deleteKeys, removing in intersection keys
	// and leaving the truly created or deleted keys in place
	updatedKeys := findIntersection(createKeys, deleteKeys)

	// build the diff nodes for the updated accounts using the mappings at both A and B as directed by the keys found as the intersection of the two
	updatedAccounts, err := sdb.buildAccountUpdates(diffAccountsAtB, diffAccountsAtA, updatedKeys, params.WatchedStorageSlots, params.IntermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for updated accounts: %v", err)
	}
	// build the diff nodes for created accounts
	createdAccounts, err := sdb.buildAccountCreations(diffAccountsAtB, params.WatchedStorageSlots, params.IntermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for created accounts: %v", err)
	}
	// build the diff nodes for deleted accounts
	deletedAccounts, err := sdb.buildAccountDeletions(diffAccountsAtA)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for deleted accounts: %v", err)
	}

	// assemble all of the nodes into the statediff object, including the intermediate nodes
	return StateDiff{
		BlockNumber: args.BlockNumber,
		BlockHash:   args.BlockHash,
		Nodes:       append(append(append(append(updatedAccounts, createdAccounts...), deletedAccounts...), createdOrUpdatedIntermediateNodes...), deletedIntermediateNodes...),
	}, nil
}

func (sdb *builder) buildStateDiffWithoutIntermediateStateNodes(args Args, params Params) (StateDiff, error) {
	// Load tries for old (A) and new (B) states
	oldTrie, err := sdb.stateCache.OpenTrie(args.OldStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for oldStateRoot: %v", err)
	}
	newTrie, err := sdb.stateCache.OpenTrie(args.NewStateRoot)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error creating trie for newStateRoot: %v", err)
	}

	// collect a map of their leafkey to all the accounts that were touched and exist at B
	diffAccountsAtB, err := sdb.collectDiffAccounts(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}), params.WatchedAddresses)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting createdAndUpdatedNodes: %v", err)
	}

	// collect a map of their leafkey to all the accounts that were touched and exist at A
	diffAccountsAtA, err := sdb.collectDiffAccounts(newTrie.NodeIterator([]byte{}), oldTrie.NodeIterator([]byte{}), params.WatchedAddresses)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error collecting deletedOrUpdatedNodes: %v", err)
	}

	// collect and sort the leafkeys for both account mappings into a slice
	createKeys := sortKeys(diffAccountsAtB)
	deleteKeys := sortKeys(diffAccountsAtA)

	// and then find the intersection of these keys
	// these are the leafkeys for the accounts which exist at both A and B but are different
	// this also mutates the passed in createKeys and deleteKeys, removing in intersection keys
	// and leaving the truly created or deleted keys in place
	updatedKeys := findIntersection(createKeys, deleteKeys)

	// build the diff nodes for the updated accounts using the mappings at both A and B as directed by the keys found as the intersection of the two
	updatedAccounts, err := sdb.buildAccountUpdates(diffAccountsAtB, diffAccountsAtA, updatedKeys, params.WatchedStorageSlots, params.IntermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for updated accounts: %v", err)
	}
	// build the diff nodes for created accounts
	createdAccounts, err := sdb.buildAccountCreations(diffAccountsAtB, params.WatchedStorageSlots, params.IntermediateStorageNodes)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for created accounts: %v", err)
	}
	// build the diff nodes for deleted accounts
	deletedAccounts, err := sdb.buildAccountDeletions(diffAccountsAtA)
	if err != nil {
		return StateDiff{}, fmt.Errorf("error building diff for deleted accounts: %v", err)
	}

	// assemble all of the nodes into the statediff object
	return StateDiff{
		BlockNumber: args.BlockNumber,
		BlockHash:   args.BlockHash,
		Nodes:       append(append(updatedAccounts, createdAccounts...), deletedAccounts...),
	}, nil
}

// collectDiffAccounts returns a mapping of their leafkeys to all the accounts that exist in a different state at B than A
// restricts the returned set to the watchedAddresses if any are provided
func (sdb *builder) collectDiffAccounts(a, b trie.NodeIterator, watchedAddresses []common.Address) (AccountMap, error) {
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

// createdAndUpdatedNodes returns a slice of all the intermediate nodes that exist in a different state at B than A
// a mapping of their leafkeys to all the accounts that exist in a different state at B than A
// and a slice of the paths for all of the nodes included in both
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

// deletedOrUpdatedNodes returns a slice of all the intermediate nodes that exist at A but not at B
// a mapping of their leafkeys to all the accounts that exist in a different state at A than B
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
			// that means the node at this path was deleted in B
			// emit an empty "removed" diff to signify as such
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

// buildAccountUpdates uses the account diffs maps for A => B and B => A and the known intersection of their leafkeys
// to generate the statediff node objects for all of the accounts that existed at both A and B but in different states
// needs to be called before building account creations and deletions as this mutates
// those account maps to remove the accounts which were updated
func (sdb *builder) buildAccountUpdates(creations, deletions AccountMap, updatedKeys []string, watchedStorageKeys []common.Hash, intermediateStorageNodes bool) ([]StateNode, error) {
	updatedAccounts := make([]StateNode, 0, len(updatedKeys))
	var err error
	for _, key := range updatedKeys {
		createdAcc := creations[key]
		deletedAcc := deletions[key]
		var storageDiffs []StorageNode
		if deletedAcc.Account != nil && createdAcc.Account != nil {
			oldSR := deletedAcc.Account.Root
			newSR := createdAcc.Account.Root
			storageDiffs, err = sdb.buildStorageNodesIncremental(oldSR, newSR, watchedStorageKeys, intermediateStorageNodes)
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

// buildAccountCreations returns the statediff node objects for all the accounts that exist at B but not at A
func (sdb *builder) buildAccountCreations(accounts AccountMap, watchedStorageKeys []common.Hash, intermediateStorageNodes bool) ([]StateNode, error) {
	accountDiffs := make([]StateNode, 0, len(accounts))
	for _, val := range accounts {
		// For account creations, any storage node contained is a diff
		storageDiffs, err := sdb.buildStorageNodesEventual(val.Account.Root, watchedStorageKeys, intermediateStorageNodes)
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

// buildAccountDeletions returns the state diff "removed" empty node objects
// to represent when an account exists at A but not at B
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

// buildStorageNodesEventual builds the storage diff node objects for a created account
// i.e. it returns all the storage nodes at this state, since there is no previous state
func (sdb *builder) buildStorageNodesEventual(sr common.Hash, watchedStorageKeys []common.Hash, intermediateNodes bool) ([]StorageNode, error) {
	log.Debug("Storage Root For Eventual Diff", "root", sr.Hex())
	sTrie, err := sdb.stateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build storage diff eventual", "error", err)
		return nil, err
	}
	it := sTrie.NodeIterator(make([]byte, 0))
	return sdb.buildStorageNodesFromTrie(it, watchedStorageKeys, intermediateNodes)
}

// buildStorageNodesIncremental builds the storage diff node objects for all nodes that exist in a different state at B than A
// this assumes storage leafs cannot be deleted like accounts can be due to EIP-158
func (sdb *builder) buildStorageNodesIncremental(oldSR common.Hash, newSR common.Hash, watchedStorageKeys []common.Hash, intermediateNodes bool) ([]StorageNode, error) {
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
	return sdb.buildStorageNodesFromTrie(it, watchedStorageKeys, intermediateNodes)
}

// buildStorageNodesFromTrie returns all the storage diff node objects in the provided node interator
// if any storage keys are provided it will only return those leaf nodes
// including intermediate nodes can be turned on or off
func (sdb *builder) buildStorageNodesFromTrie(it trie.NodeIterator, watchedStorageKeys []common.Hash, intermediateNodes bool) ([]StorageNode, error) {
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
			if isWatchedStorageKey(watchedStorageKeys, leafKey) {
				storageDiffs = append(storageDiffs, StorageNode{
					NodeType:  ty,
					Path:      nodePath,
					NodeValue: node,
					LeafKey:   leafKey,
				})
			}
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

// isWatchedAddress is used to check if a state account corresponds to one of the addresses the builder is configured to watch
func isWatchedAddress(watchedAddresses []common.Address, stateLeafKey []byte) bool {
	// If we aren't watching any specific addresses, we are watching everything
	if len(watchedAddresses) == 0 {
		return true
	}
	for _, addr := range watchedAddresses {
		addrHashKey := crypto.Keccak256(addr.Bytes())
		if bytes.Equal(addrHashKey, stateLeafKey) {
			return true
		}
	}
	return false
}

// isWatchedStorageKey is used to check if a storage leaf corresponds to one of the storage slots the builder is configured to watch
func isWatchedStorageKey(watchedKeys []common.Hash, storageLeafKey []byte) bool {
	// If we aren't watching any specific addresses, we are watching everything
	if len(watchedKeys) == 0 {
		return true
	}
	for _, hashKey := range watchedKeys {
		if bytes.Equal(hashKey.Bytes(), storageLeafKey) {
			return true
		}
	}
	return false
}
