package vm

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
)

const (
	EipXXXColdAccountAccessCost = uint64(2600)
	EipXXXColdSloadCost         = uint64(2100)
	EipXXXWarmStorageReadCost   = uint64(100)
)

// gasStoreEipXXX implements gas cost for SSTORE according to EIP-TBD
//
// When calling SSTORE, check if the (address, storage_key) pair is in accessed_storage_keys.
// If it is not, charge an additional 2000 gas, and add the pair to accessed_storage_keys.
// Additionally,
//	- reduce the gas cost of changing a storage slot from a nonzero value to
//	  another nonzero value from 5000 to 3000, and
// 	- the refund for resetting a value from 4800 to 2800
// rules stay the same as in EIP 1283, only those two constants change.
//
// 0. If *gasleft* is less than or equal to 2300, fail the current call.
//         -- the point below is modified by ACL EIP: 800 to 100--
// 1. If current value equals new value (this is a no-op), SSTORE_NOOP_GAS gas is deducted.
// 2. If current value does not equal new value:
//   2.1. If original value equals current value (this storage slot has not been changed by the current execution context):
//     2.1.1. If original value is 0, SSTORE_INIT_GAS gas is deducted.
//     2.1.2. Otherwise, SSTORE_CLEAN_GAS gas is deducted. If new value is 0, add SSTORE_CLEAR_REFUND to refund counter.
//   2.2. If original value does not equal current value (this storage slot is dirty), SSTORE_DIRTY_GAS gas is deducted. Apply both of the following clauses:
//     2.2.1. If original value is not 0:
//       2.2.1.1. If current value is 0 (also means that new value is not 0), subtract SSTORE_CLEAR_REFUND gas from refund counter. We can prove that refund counter will never go below 0.
//       2.2.1.2. If new value is 0 (also means that current value is not 0), add SSTORE_CLEAR_REFUND gas to refund counter.
//     2.2.2. If original value equals new value (this storage slot is reset):
//       2.2.2.1. If original value is 0, add SSTORE_INIT_REFUND to refund counter.
//       2.2.2.2. Otherwise, add SSTORE_CLEAN_REFUND gas to refund counter
func gasSStoreEipXXX(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// If we fail the minimum gas availability invariant, fail (0)
	if contract.Gas <= params.SstoreSentryGasEIP2200 {
		return 0, errors.New("not enough gas for reentrancy sentry")
	}
	// Gas sentry honoured, do the actual gas calculation based on the stored value
	var (
		y, x    = stack.Back(1), stack.Back(0)
		slot    = common.Hash(x.Bytes32())
		current = evm.StateDB.GetState(contract.Address(), slot)
		cost    = uint64(0)
	)
	// Check slot presence in the access list
	if _, slotPresent := evm.StateDB.SlotInAccessList(contract.Address(), slot); !slotPresent {
		cost = EipXXXColdSloadCost
		// If the caller cannot afford the cost, this change will be rolled back
		// If he does afford it, we can skip checking the same thing later on, during execution
		evm.StateDB.AddAccessListSlot(contract.Address(), slot)
	}
	value := common.Hash(y.Bytes32())

	if current == value { // noop (1)
		//return cost + params.SstoreNoopGasEIP2200, nil
		return cost + EipXXXWarmStorageReadCost, nil // SLOAD_GAS
	}
	original := evm.StateDB.GetCommittedState(contract.Address(), common.Hash(x.Bytes32()))
	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return cost + params.SstoreInitGasEIP2200, nil
		}
		if value == (common.Hash{}) { // delete slot (2.1.2b)
			evm.StateDB.AddRefund(params.SstoreClearRefundEIP2200)
		}
		//return params.SstoreCleanGasEIP2200, nil
		return cost + (5000 - EipXXXColdSloadCost), nil // write existing slot (2.1.2)
	}
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			evm.StateDB.SubRefund(params.SstoreClearRefundEIP2200)
		} else if value == (common.Hash{}) { // delete slot (2.2.1.2)
			evm.StateDB.AddRefund(params.SstoreClearRefundEIP2200)
		}
	}
	if original == value {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			evm.StateDB.AddRefund(params.SstoreInitRefundEIP2200)
		} else { // reset to original existing slot (2.2.2.2)
			evm.StateDB.AddRefund(params.SstoreCleanRefundEIP2200)
		}
	}
	//return cost + params.SstoreDirtyGasEIP2200, nil // dirty update (2.2)
	return cost + EipXXXWarmStorageReadCost, nil // dirty update (2.2)
}

// gasSloadEipXXX calculates dynamic gas for SLOAD according to EIP-XXX
// For SLOAD, if the (address, storage_key) pair (where address is the address of the contract
// whose storage is being read) is not yet in accessed_storage_keys,
// charge 2000 gas and add the pair to accessed_storage_keys.
// If the pair is already in accessed_storage_keys, charge 100 gas.
func gasSloadEipXXX(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	loc := stack.peek()
	slot := common.Hash(loc.Bytes32())
	// Check slot presence in the access list
	if _, slotPresent := evm.StateDB.SlotInAccessList(contract.Address(), slot); !slotPresent {
		// If the caller cannot afford the cost, this change will be rolled back
		// If he does afford it, we can skip checking the same thing later on, during execution
		evm.StateDB.AddAccessListSlot(contract.Address(), slot)

		// We return cold-warm, since EipXXXWarmStorageReadCost is already charged as constantGas
		return EipXXXColdSloadCost - EipXXXWarmStorageReadCost, nil
	}
	return 0, nil
}

func gasExtCodeCopyEIPXXX(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// memory expansion
	gas, err := gasExtCodeCopy(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	addr := common.Address(stack.peek().Bytes20())
	// Check slot presence in the access list
	if !evm.StateDB.AddrInAccessList(addr) {
		// If the caller cannot afford the cost, this change will be rolled back
		evm.StateDB.AddAccessListAccount(addr)
		var overflow bool
		if gas, overflow = math.SafeAdd(gas, EipXXXColdAccountAccessCost-EipXXXWarmStorageReadCost); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
	return gas, nil
}

// gasAccessListAccount checks whether the first stack item (as address) is present in the access list.
// If it is, this method returns '0', otherwise '2400' gas.
// This method is used by:
// - extcodehash,
// - extcodesize,
// - (ext) balance
func gasAccessListAccount(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	addr := common.Address(stack.peek().Bytes20())
	// Check slot presence in the access list
	if !evm.StateDB.AddrInAccessList(addr) {
		// If the caller cannot afford the cost, this change will be rolled back
		evm.StateDB.AddAccessListAccount(addr)
		// The warm storage read cost is already charged as constantGas
		return EipXXXColdAccountAccessCost - EipXXXWarmStorageReadCost, nil
	}
	return 0, nil
}

func makeCallVariantGasCalEipXXX(oldCalculator gasFunc) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		gas := uint64(0)
		addr := common.Address(stack.Back(1).Bytes20())
		// Check slot presence in the access list
		if !evm.StateDB.AddrInAccessList(addr) {
			// If the caller cannot afford the cost, this change will be rolled back
			evm.StateDB.AddAccessListAccount(addr)
			// EipXXXWarmStorageReadCost (100) is already deducted in the form of a constant cost
			gas = EipXXXColdAccountAccessCost - EipXXXWarmStorageReadCost
		}
		// Now call the old calculator, which takes into account
		// - create new account
		// - transfer value
		// - memory expansion
		// - 63/64ths rule
		gasB, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if err != nil {
			return 0, err
		}
		var overflow bool
		if gas, overflow = math.SafeAdd(gas, gasB); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

var (
	gasCallEipXXX         = makeCallVariantGasCalEipXXX(gasCall)
	gasDelegateCallEipXXX = makeCallVariantGasCalEipXXX(gasDelegateCall)
	gasStaticCallEipXXX   = makeCallVariantGasCalEipXXX(gasStaticCall)
	gasCallCodeEipXXX     = makeCallVariantGasCalEipXXX(gasCallCode)
)

func gasSelfdestructEipXXX(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		gas     uint64
		address = common.Address(stack.Back(0).Bytes20())
	)
	if !evm.StateDB.AddrInAccessList(address) {
		// If the caller cannot afford the cost, this change will be rolled back
		evm.StateDB.AddAccessListAccount(address)
		gas = EipXXXColdAccountAccessCost
	}
	// if empty and transfers value
	if evm.StateDB.Empty(address) && evm.StateDB.GetBalance(contract.Address()).Sign() != 0 {
		gas += params.CreateBySelfdestructGas
	}
	if !evm.StateDB.HasSuicided(contract.Address()) {
		evm.StateDB.AddRefund(params.SelfdestructRefundGas)
	}
	return gas, nil

}
