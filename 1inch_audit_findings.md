1inch Audit_ call data

Security Finding in contracts/libraries/RemainingInvalidatorLib.sol
Finding ID: 72acf085-bb33-4235-a9ab-530ab7a67ff8
Severity: HIGH
Matched Rule: 
Title: Off-by-one Underflow in remains() Leading to Invalidator Reset
Description: The function `remains(uint256 remainingMakingAmount, uint256 makingAmount)` computes the invalidator as the bitwise NOT of an unchecked subtraction `remainingMakingAmount - makingAmount`. When `remainingMakingAmount < makingAmount`, this subtraction underflows and wraps, causing the computed invalidator to equal `filledAmount - 1`. In particular, if the first fill amount is `1`, the invalidator becomes 0. A zero invalidator is treated as a 'new order' (`isNewOrder` returns true), allowing the order to be refilled and leading to potential double-spending or replay of fills.
Recommendation: Adjust the invalidator calculation to avoid the off-by-one underflow. Compute the invalidator directly as `~remainingMakingAmount` under unchecked context, and use `fullyFilled()` when `remainingMakingAmount == 0`. Remove or correct the subtraction of `makingAmount`.
Impacted Code :
```
function remains(uint256 remainingMakingAmount, uint256 makingAmount) internal pure returns(RemainingInvalidator) {
    unchecked {
        return RemainingInvalidator.wrap(~(remainingMakingAmount - makingAmount));
    }
}
```
Context Used:
- Searched repo for 'remains('
- contracts/OrderMixin.sol #L300-L400
- Searched repo for 'isNewOrder'
- contracts/OrderMixin.sol #L400-L480

Security Finding in contracts/helpers/SafeOrderBuilder.sol
Finding ID: f629c224-ab24-45bd-8d61-17475a4d776a
Severity: HIGH
Matched Rule: 
Title: Unverified Oracle Original Answer Parameter
Description: The contract adjusts `order.takingAmount` using the maker/taker `originalAnswer` parameters provided by the caller without verifying that these match any on-chain historical oracle data. A malicious maker could supply arbitrary `originalAnswer` values to inflate or deflate the `takingAmount` favorably, breaking the intended volatility adjustment logic.
Recommendation: Include and verify a specific `roundId` or historical answer from the oracle. For example, require the caller to provide `roundId` and then fetch `oracle.getRoundData(roundId)` to confirm that `originalAnswer` matches the reported `answer` before performing the adjustment.
Impacted Code :
```
(maker asset adjustment)
(, int256 latestAnswer,, uint256 updatedAt,) = makerAssetOracleParams.oracle.latestRoundData();
if (updatedAt + makerAssetOracleParams.ttl < block.timestamp) revert StaleOraclePrice();
order.takingAmount = order.takingAmount.mulDiv(uint256(latestAnswer), makerAssetOracleParams.originalAnswer);

(taker asset adjustment)
(, int256 latestAnswer,, uint256 updatedAt,) = takerAssetOracleParams.oracle.latestRoundData();
if (updatedAt + takerAssetOracleParams.ttl < block.timestamp) revert StaleOraclePrice();
order.takingAmount = order.takingAmount.mulDiv(takerAssetOracleParams.originalAnswer, uint256(latestAnswer));
```
Context Used:
- contracts/interfaces/IOrderMixin.sol #L13-L214
- contracts/interfaces/IOrderRegistrator.sol #L12-L28


Security Finding in contracts/extensions/OrderIdInvalidator.sol
Finding ID: 3a2bfaba-70fb-4027-8d48-aea16feb1adc
Severity: HIGH
Matched Rule: 
Title: Replay Vulnerability: OrderIdInvalidator Allows Unlimited Reuse of Same Order
Description: OrderIdInvalidator is intended to enforce single execution per (maker, orderId) by storing the initial orderHash and rejecting mismatched hashes. However, the logic in preInteraction only reverts when the incoming orderHash differs from the stored value. If the same orderHash is reused, the check passes, allowing unlimited replays of the identical order.
Recommendation: Change the logic to disallow any subsequent calls once an orderId has been used. For example, after the first execution, always revert on storedOrderHash != 0, regardless of hash matching. Alternatively, delete or mark the mapping entry after first use so that storedOrderHash is non-zero and triggers a revert on any further invocation.
Impacted Code :
```
function preInteraction(
    IOrderMixin.Order calldata order,
    bytes calldata /* extension */,
    bytes32 orderHash,
    address /* taker */,
    uint256 /* makingAmount */,
    uint256 /* takingAmount */,
    uint256 /* remainingMakingAmount */,
    bytes calldata extraData
) external onlyLimitOrderProtocol {
    uint32 orderId = uint32(bytes4(extraData));
    bytes32 storedOrderHash = _ordersIdsHashes[order.maker.get()][orderId];
    if (storedOrderHash == 0x0) {
        _ordersIdsHashes[order.maker.get()][orderId] = orderHash;
    } else if (storedOrderHash != orderHash) {
        revert InvalidOrderHash();
    }
}
```
Missing access control allowing arbitrary Safe message approval
OPEN


Created: Sep 27, 2025, 6:29 PM
•
1inch/limit-order-proto…
contracts/helpers/SafeOrderBuilder.sol
DESCRIPTION

The function buildAndSignOrder (lines 47-73) is declared external with no access control. It writes directly to the Safe’s signedMessages mapping (inherited via GnosisSafeStorage) by setting signedMessages[msgHash] = 1, thereby approving any order hash as validly signed by the Safe. An attacker can call this method, causing the Safe to believe it has pre-approved arbitrary limit orders without any owner signatures or threshold approvals. Impact: Enables anyone to pre-approve and register orders that execute token transfers or other actions as if the Safe’s owners had signed off. This completely undermines the Safe’s signature threshold and owner controls.
RECOMMENDATION
Restrict buildAndSignOrder so that only authorized Safe owners or a trusted module can invoke it. For example, add a check such as require(msg.sender == this.getOwners()[0], "Not owner"); or integrate the Safe’s module/guard framework. Alternatively, move the signedMessages[msgHash] = 1 call behind a proper execTransaction on the Safe itself.
IMPACTED CODE

bytes32 msgHash = _getMessageHash(abi.encode(_LIMIT_ORDER_PROTOCOL.hashOrder(order)));
signedMessages[msgHash] = 1;


simulate() can lead to contract self-destruction
OPEN


Created: Sep 5, 2025, 6:17 PM
•
1inch/limit-order-proto…
contracts/OrderMixin.sol
DESCRIPTION

The simulate function (lines 71-75) uses delegatecall to an arbitrary target contract and then unconditionally reverts to return results. However, if the target contract’s code contains a selfdestruct opcode, the delegatecall will execute in the context of this contract, causing the OrderMixin contract to be destroyed. The subsequent revert cannot undo the selfdestruct. This allows any user to destroy the OrderMixin contract permanently.
RECOMMENDATION
Remove or restrict simulate, or at minimum whitelist safe target contracts. Alternatively, change delegatecall to staticcall, which cannot modify state or selfdestruct.
IMPACTED CODE

function simulate(address target, bytes calldata data) external {
    // solhint-disable-next-line avoid-low-level-calls
    (bool success, bytes memory result) = target.delegatecall(data);
    revert SimulationResults(success, result);
}
CONTEXT USED

Resources accessed by the model to generate this finding

contracts/OrderLib.sol #L21-L163

Security Finding in src/AquaApp.sol
Finding ID: c2ff5dcf-5ba1-4377-a823-a63311e5c2fd
Severity: LOW
Matched Rule: 
Title: Reentrancy lock check can be bypassed with different strategyHash
Description: The `_safeCheckAquaPush` function checks that `_reentrancyLocks[strategyHash].isLocked()` returns true to ensure the caller is using reentrancy protection. However, this check only validates that the specific `strategyHash` is locked. An attacker could potentially call a swap function with a different `strategyHash` that is already locked (from a previous nested call), bypassing the intended reentrancy protection.

The check at line 39 verifies:
```solidity
require(_reentrancyLocks[strategyHash].isLocked(), MissingNonReentrantModifier());
```

This only ensures that the provided `strategyHash` is locked, but doesn't verify that the current execution context is the one that acquired the lock. If an attacker can manipulate the `strategyHash` parameter or if there's a way to call with a pre-locked strategyHash, the protection could be circumvented.
Recommendation: Consider using a global reentrancy lock in addition to the per-strategy lock, or ensure that the strategyHash used in `_safeCheckAquaPush` is derived from immutable parameters that cannot be manipulated by the caller. The contract documentation suggests using `nonReentrantStrategy(keccak256(abi.encode(strategy)))` which ties the lock to the strategy, but inheriting contracts must ensure the strategyHash parameter cannot be controlled by untrusted input.
Impacted Code :
```
require(_reentrancyLocks[strategyHash].isLocked(), MissingNonReentrantModifier());
```
Context Used:
- src/interfaces/IAqua.sol #L10-L98
- src/libs/TransientLock.sol #L9-L11
- src/libs/Transient.sol #L1-L137
- src/libs/TransientLock.sol #L1-L37
- Listed files in 'examples/apps'
- Listed files in 'src'
- src/Aqua.sol #L1-L91
- src/AquaRouter.sol #L1-L15
- src/libs/TransientLock.sol #L13-L33

Security Finding in src/libs/ReentrancyGuard.sol
Finding ID: 2d89f4c3-80b3-4ec1-8f51-f8bf46cf9c6c
Severity: LOW
Matched Rule: 
Title: Pragma Version Mismatch Allows Compilation with Incompatible Solidity
Description: The ReentrancyGuard.sol file uses `pragma solidity ^0.8.0` but imports TransientLock.sol which uses transient storage opcodes (tload/tstore) that are only available since Solidity 0.8.24. The comment on line 2 acknowledges this: `// tload/tstore are available since 0.8.24`. However, the pragma allows compilation with any version from 0.8.0 onwards.

If this contract is compiled with a Solidity version between 0.8.0 and 0.8.23, the compilation will fail when the compiler encounters the tload/tstore opcodes in the imported TransientLock.sol (which correctly uses `^0.8.24`). This creates a confusing developer experience and could lead to unexpected build failures.

The TransientLock.sol file correctly uses `pragma solidity ^0.8.24` and Transient.sol also uses `pragma solidity ^0.8.24`, but ReentrancyGuard.sol which imports and depends on these files uses the incorrect `^0.8.0` pragma.
Recommendation: Change the pragma version in ReentrancyGuard.sol from `pragma solidity ^0.8.0` to `pragma solidity ^0.8.24` to match the minimum required version for transient storage opcodes and align with the imported TransientLock.sol dependency.
Impacted Code :
```
pragma solidity ^0.8.0; // tload/tstore are available since 0.8.24
```
Context Used:
- Searched repo for 'pragma solidity'
- Searched repo for 'nonReentrant'
- src/AquaApp.sol #L1-L48
- src/libs/TransientLock.sol #L1-L33
- src/libs/Transient.sol #L1-L137
- Searched repo for 'ReentrancyGuard'
- examples/apps/XYCSwap.sol #L1-L132

Security Finding in src/libs/Simulator.sol
Finding ID: 278aa8b3-3b53-4293-99d8-d7bad2520be9
Severity: MEDIUM
Matched Rule: 
Title: Arbitrary Delegatecall Allows Storage Manipulation
Description: The `simulate` function in the `Simulator` contract performs a `delegatecall` to an arbitrary address with arbitrary calldata. Since `AquaRouter` inherits from both `Aqua` and `Simulator`, calling `simulate` on the `AquaRouter` contract allows anyone to execute arbitrary code in the context of `AquaRouter`, potentially manipulating its storage.

While the function always reverts with the `Simulated` error after the delegatecall, the delegatecall itself executes before the revert. In Solidity, storage modifications made during a delegatecall that later reverts are rolled back. However, this pattern is dangerous because:

1. If the delegatecall target performs external calls that have side effects (e.g., transferring ETH, calling other contracts), those side effects may persist even if the outer call reverts.
2. The function accepts `payable`, meaning ETH can be sent with the call. If the delegatecall target is a malicious contract that forwards ETH to another address, that ETH transfer would persist.
3. Future code changes or compiler optimizations could potentially change the behavior.

The intended use appears to be for simulation/dry-run purposes, but the implementation allows arbitrary code execution in the contract's context.
Recommendation: Consider restricting the `simulate` function to only allow delegatecalls to trusted/whitelisted addresses, or implement a more controlled simulation mechanism that doesn't involve arbitrary delegatecall. Alternatively, if the function is only meant for off-chain simulation, consider making it a view function that uses `staticcall` instead, or add access control to limit who can call it.
Impacted Code :
```
function simulate(address delegatee, bytes calldata data) external payable {
    (bool success, bytes memory result) = delegatee.delegatecall(data);
    revert Simulated(delegatee, data, success, result);
}
```
Context Used:
- src/Aqua.sol #L1-L91
- Listed files in 'src/libs'
- src/AquaRouter.sol #L1-L15
- Searched repo for 'simulate'
- test/Aqua.t.sol #L1-L489
- Searched repo for 'Simulator'
- src/libs/Multicall.sol #L1-L24

Security Finding in src/Aqua.sol
Finding ID: 54d14a79-b83c-4ae4-94bf-6fd93219e297
Severity: CRITICAL
Matched Rule: 
Title: Arbitrary Delegatecall in Simulator Enables Code Execution
Description: The `AquaRouter` contract inherits from `Simulator`, which contains a `simulate` function that performs an arbitrary `delegatecall` to any address with any data. Since `delegatecall` executes code in the context of the calling contract (AquaRouter), a malicious actor could:

1. Call `simulate` with a malicious contract address that contains code to manipulate AquaRouter's storage
2. Potentially corrupt the `_balances` mapping or other state variables
3. Execute arbitrary logic with AquaRouter's permissions

While the function always reverts with `Simulated` error, the delegatecall still executes and can modify storage before the revert. In Solidity, storage modifications made during a delegatecall that later reverts are NOT rolled back if the revert happens in the outer call context after the delegatecall completes successfully.
Recommendation: 1. Remove the `Simulator` inheritance from `AquaRouter` if simulation functionality is not needed in production
2. If simulation is required, implement it as a separate contract that doesn't share storage with the main protocol
3. Add access control to restrict who can call `simulate`
4. Consider using `staticcall` instead of `delegatecall` for read-only simulations
Impacted Code :
```
contract Simulator {
    error Simulated(address delegatee, bytes data, bool success, bytes result);

    function simulate(address delegatee, bytes calldata data) external payable {
        (bool success, bytes memory result) = delegatee.delegatecall(data);
        revert Simulated(delegatee, data, success, result);
    }
}
```
Context Used:
- src/AquaRouter.sol #L1-L15
- test/Aqua.t.sol #L124-L485
- src/libs/Balance.sol #L7-L10
- Searched repo for 'duplicate'
- src/libs/Balance.sol #L1-L33
- Searched repo for 'tokens\.length == amounts\.length'
- Searched repo for 'safeTransferFrom'
- src/libs/Multicall.sol #L1-L24
- Searched repo for 'require.*length'
- examples/test/XYCNestedSwaps.t.sol #L155-L304
- test/Aqua.t.sol #L189-L485
- src/libs/Simulator.sol #L1-L18
- src/libs/Balance.sol #L12-L29
- test/AquaStorageTest.t.sol #L54-L114
- examples/apps/XYCSwap.sol #L40-L123
- Searched repo for 'tokens.length.*amounts.length'
- src/AquaApp.sol #L1-L48
- src/interfaces/IAqua.sol #L10-L98
- examples/test/XYCNestedSwaps.t.sol #L225-L487
- test/AquaStorageTest.t.sol #L36-L96
- examples/test/XYCSwap.t.sol #L685-L718
- Searched repo for 'unique'

———————————————————————————————————————————————————

External Interactions: Arbitrary Delegatecall in Simulator Enables Code Execution

src/Aqua.sol

DESCRIPTION

The AquaRouter contract inherits from Simulator, which contains a simulate function that performs an arbitrary delegatecall to any address with any data. Since delegatecall executes code in the context of the calling contract (AquaRouter), a malicious actor could: 1. Call simulate with a malicious contract address that contains code to manipulate AquaRouter's storage 2. Potentially corrupt the _balances mapping or other state variables 3. Execute arbitrary logic with AquaRouter's permissions While the function always reverts with Simulated error, the delegatecall still executes and can modify storage before the revert. In Solidity, storage modifications made during a delegatecall that later reverts are NOT rolled back if the revert happens in the outer call context after the delegatecall completes successfully.
RECOMMENDATION
1. Remove the Simulator inheritance from AquaRouter if simulation functionality is not needed in production 2. If simulation is required, implement it as a separate contract that doesn't share storage with the main protocol 3. Add access control to restrict who can call simulate 4. Consider using staticcall instead of delegatecall for read-only simulations
IMPACTED CODE

contract Simulator {
    error Simulated(address delegatee, bytes data, bool success, bytes result);

    function simulate(address delegatee, bytes calldata data) external payable {
        (bool success, bytes memory result) = delegatee.delegatecall(data);
        revert Simulated(delegatee, data, success, result);
    }
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaRouter.sol #L1-L15


test/Aqua.t.sol #L124-L485


src/libs/Balance.sol #L7-L10

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


MEDIUM
External Interactions: Arbitrary Delegatecall Allows Storage Manipulation

src/libs/Simulator.sol

DESCRIPTION

The simulate function in the Simulator contract performs a delegatecall to an arbitrary address with arbitrary calldata. Since AquaRouter inherits from both Aqua and Simulator, calling simulate on the AquaRouter contract allows anyone to execute arbitrary code in the context of AquaRouter, potentially manipulating its storage. While the function always reverts with the Simulated error after the delegatecall, the delegatecall itself executes before the revert. In Solidity, storage modifications made during a delegatecall that later reverts are rolled back. However, this pattern is dangerous because: 1. If the delegatecall target performs external calls that have side effects (e.g., transferring ETH, calling other contracts), those side effects may persist even if the outer call reverts. 2. The function accepts payable, meaning ETH can be sent with the call. If the delegatecall target is a malicious contract that forwards ETH to another address, that ETH transfer would persist. 3. Future code changes or compiler optimizations could potentially change the behavior. The intended use appears to be for simulation/dry-run purposes, but the implementation allows arbitrary code execution in the contract's context.
RECOMMENDATION
Consider restricting the simulate function to only allow delegatecalls to trusted/whitelisted addresses, or implement a more controlled simulation mechanism that doesn't involve arbitrary delegatecall. Alternatively, if the function is only meant for off-chain simulation, consider making it a view function that uses staticcall instead, or add access control to limit who can call it.
IMPACTED CODE

function simulate(address delegatee, bytes calldata data) external payable {
    (bool success, bytes memory result) = delegatee.delegatecall(data);
    revert Simulated(delegatee, data, success, result);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/Aqua.sol #L1-L91


src/AquaRouter.sol #L1-L15


test/Aqua.t.sol #L1-L489

Show 4 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


MEDIUM
Reentrancy: Multicall Delegatecall Enables Reentrancy Attacks

src/AquaRouter.sol

DESCRIPTION

The Multicall.multicall() function allows batching multiple calls via delegatecall to address(this). This pattern, combined with the lack of reentrancy protection in the core Aqua contract functions (ship, dock, pull, push), creates potential reentrancy vectors. Specifically: 1. The pull() function calls safeTransferFrom() which can trigger callbacks on ERC777 tokens or tokens with hooks 2. The push() function similarly calls safeTransferFrom() which can trigger callbacks 3. During these callbacks, an attacker could re-enter through multicall() to manipulate balances before the original operation completes While the Aqua contract uses SafeERC20 and the balance updates happen before transfers in pull(), the push() function updates balance before the transfer, which could be exploited with malicious tokens. The AquaApp base contract provides reentrancy protection via nonReentrantStrategy modifier, but the core Aqua contract itself has no such protection.
RECOMMENDATION
1. Add reentrancy guards to the Aqua contract's pull() and push() functions using the existing ReentrancyGuard library 2. Follow the checks-effects-interactions pattern consistently 3. Consider adding a global reentrancy lock for the multicall() function 4. Document that the protocol should only be used with standard ERC20 tokens without transfer hooks
IMPACTED CODE

function multicall(bytes[] calldata data) external {
    for (uint256 i = 0; i < data.length; i++) {
        (bool success,) = address(this).delegatecall(data[i]);
        if (!success) {
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/libs/ReentrancyGuard.sol #L1-L60


src/libs/Simulator.sol #L1-L14


src/libs/Transient.sol #L1-L137

Show 13 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


MEDIUM
Logic & Business Rules: Fee-on-Transfer Tokens Cause Accounting Mismatch

src/Aqua.sol

DESCRIPTION

The pull and push functions update internal balance accounting based on the amount parameter, then transfer tokens using safeTransferFrom. For fee-on-transfer (deflationary) tokens, the actual amount received by the recipient will be less than amount due to the transfer fee. This creates a discrepancy between the recorded balance in _balances and the actual tokens transferred. In pull (line 69-76): The balance is decremented by amount, but the recipient receives amount - fee. In push (line 78-86): The balance is incremented by amount, but the maker receives amount - fee. This can lead to situations where: 1. A strategy's recorded balance exceeds what the maker actually has available 2. Subsequent pulls may fail due to insufficient actual token balance despite sufficient recorded balance
RECOMMENDATION
Either: 1. Document that fee-on-transfer tokens are not supported and add a token whitelist mechanism, or 2. Measure actual token transfers by checking balances before and after the transfer:

uint256 balanceBefore = IERC20(token).balanceOf(to);
IERC20(token).safeTransferFrom(maker, to, amount);
uint256 actualReceived = IERC20(token).balanceOf(to) - balanceBefore;
// Use actualReceived for accounting
IMPACTED CODE

function pull(address maker, bytes32 strategyHash, address token, uint256 amount, address to) external {
    Balance storage balance = _balances[maker][msg.sender][strategyHash][token];
    (uint248 prevBalance, uint8 tokensCount) = balance.load();
    balance.store(prevBalance - amount.toUint248(), tokensCount);

    IERC20(token).safeTransferFrom(maker, to, amount);
    emit Pulled(maker, msg.sender, strategyHash, token, amount);
}

function push(address maker, address app, bytes32 strategyHash, address token, uint256 amount) external {
    Balance storage balance = _balances[maker][app][strategyHash][token];
    (uint248 prevBalance, uint8 tokensCount) = balance.load();
    require(tokensCount > 0 && tokensCount != _DOCKED, PushToNonActiveStrategyPrevented(maker, app, strategyHash, token));
    balance.store(prevBalance + amount.toUint248(), tokensCount);

    IERC20(token).safeTransferFrom(msg.sender, maker, amount);
    emit Pushed(maker, app, strategyHash, token, amount);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaRouter.sol #L1-L15


test/Aqua.t.sol #L124-L485


src/libs/Balance.sol #L7-L10

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Logic & Business Rules: Pragma Version Mismatch Allows Compilation with Incompatible Solidity

src/libs/ReentrancyGuard.sol

DESCRIPTION

The ReentrancyGuard.sol file uses pragma solidity ^0.8.0 but imports TransientLock.sol which uses transient storage opcodes (tload/tstore) that are only available since Solidity 0.8.24. The comment on line 2 acknowledges this: // tload/tstore are available since 0.8.24. However, the pragma allows compilation with any version from 0.8.0 onwards. If this contract is compiled with a Solidity version between 0.8.0 and 0.8.23, the compilation will fail when the compiler encounters the tload/tstore opcodes in the imported TransientLock.sol (which correctly uses ^0.8.24). This creates a confusing developer experience and could lead to unexpected build failures. The TransientLock.sol file correctly uses pragma solidity ^0.8.24 and Transient.sol also uses pragma solidity ^0.8.24, but ReentrancyGuard.sol which imports and depends on these files uses the incorrect ^0.8.0 pragma.
RECOMMENDATION
Change the pragma version in ReentrancyGuard.sol from pragma solidity ^0.8.0 to pragma solidity ^0.8.24 to match the minimum required version for transient storage opcodes and align with the imported TransientLock.sol dependency.
IMPACTED CODE

pragma solidity ^0.8.0; // tload/tstore are available since 0.8.24
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaApp.sol #L1-L48


src/libs/TransientLock.sol #L1-L33


src/libs/Transient.sol #L1-L137

Show 4 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Reentrancy: Reentrancy lock check can be bypassed with different strategyHash

src/AquaApp.sol

DESCRIPTION

The _safeCheckAquaPush function checks that _reentrancyLocks[strategyHash].isLocked() returns true to ensure the caller is using reentrancy protection. However, this check only validates that the specific strategyHash is locked. An attacker could potentially call a swap function with a different strategyHash that is already locked (from a previous nested call), bypassing the intended reentrancy protection. The check at line 39 verifies:

require(_reentrancyLocks[strategyHash].isLocked(), MissingNonReentrantModifier());
This only ensures that the provided strategyHash is locked, but doesn't verify that the current execution context is the one that acquired the lock. If an attacker can manipulate the strategyHash parameter or if there's a way to call with a pre-locked strategyHash, the protection could be circumvented.
RECOMMENDATION
Consider using a global reentrancy lock in addition to the per-strategy lock, or ensure that the strategyHash used in _safeCheckAquaPush is derived from immutable parameters that cannot be manipulated by the caller. The contract documentation suggests using nonReentrantStrategy(keccak256(abi.encode(strategy))) which ties the lock to the strategy, but inheriting contracts must ensure the strategyHash parameter cannot be controlled by untrusted input.
IMPACTED CODE

require(_reentrancyLocks[strategyHash].isLocked(), MissingNonReentrantModifier());
CONTEXT USED

Resources accessed by the model to generate this finding

src/interfaces/IAqua.sol #L10-L98


src/libs/TransientLock.sol #L9-L11


src/libs/Transient.sol #L1-L137

Show 6 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Arithmetic Issues: Arithmetic Underflow in Balance Subtraction

src/libs/Balance.sol

DESCRIPTION

In the pull function of Aqua.sol (line 72), the balance subtraction prevBalance - amount.toUint248() is performed without checking if prevBalance >= amount. While Solidity 0.8+ has built-in overflow/underflow protection, the subtraction happens between uint248 values. The toUint248() call from SafeCast will revert if amount > type(uint248).max, but there's no explicit check that prevBalance >= amount.toUint248(). If amount > prevBalance, the subtraction will revert due to Solidity's built-in underflow protection, but this is an implicit protection rather than an explicit business logic check with a meaningful error message.
RECOMMENDATION
Add an explicit check with a descriptive error message before the subtraction: require(prevBalance >= amount.toUint248(), InsufficientBalance(maker, strategyHash, token, prevBalance, amount));. This provides better error messages for debugging and makes the business logic explicit.
IMPACTED CODE

balance.store(prevBalance - amount.toUint248(), tokensCount);
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaApp.sol #L1-L48


src/interfaces/IAqua.sol #L1-L102


src/Aqua.sol #L1-L91

Show 15 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Reentrancy: Delegatecall in Loop Allows Reentrancy via Multicall

src/libs/Multicall.sol

DESCRIPTION

The multicall function uses delegatecall in a loop to execute multiple calls against the contract. Since delegatecall preserves the storage context and msg.sender, an attacker can batch multiple calls that interact with the same state. While the contract uses transient storage locks for reentrancy protection in AquaApp, the Multicall contract itself does not have reentrancy protection. This means that within a single multicall transaction, an attacker could potentially: 1. Call functions that modify state in unexpected sequences 2. Bypass per-call reentrancy checks since all calls happen within the same transaction context 3. Exploit state changes between batched calls For example, if a user calls multicall with calls to ship() and pull() in sequence, the state changes from ship() are immediately visible to pull() within the same transaction, potentially allowing manipulation of balances or strategy states.
RECOMMENDATION
Consider adding a reentrancy guard to the multicall function using the existing ReentrancyGuard or TransientLock mechanism. This would prevent nested multicalls and ensure that state changes are properly isolated. Alternatively, document the expected behavior and ensure all functions called via multicall have their own reentrancy protection.
IMPACTED CODE

function multicall(bytes[] calldata data) external {
    for (uint256 i = 0; i < data.length; i++) {
        (bool success,) = address(this).delegatecall(data[i]);
        if (!success) {
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/libs/TransientLock.sol #L1-L37


src/libs/ReentrancyGuard.sol #L1-L60


src/libs/Simulator.sol #L1-L18

Show 11 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Arithmetic Issues: Small Swaps Yield Zero Output While Consuming Input Tokens

examples/apps/XYCSwap.sol

DESCRIPTION

The _quoteExactIn function uses integer division that can round down to zero for small swap amounts. When a user performs a swap with a small amountIn, the calculation amountOut = (amountInWithFee * balanceOut) / (balanceIn + amountInWithFee) can result in amountOut = 0 due to integer division truncation. The test file confirms this behavior at line 438-445 where swaps of 1 or 2 tokens result in 0 output. The issue is that the swap still proceeds - the user's input tokens are transferred to the pool via the callback mechanism, but they receive nothing in return. While the amountOutMin parameter provides slippage protection, if a user sets amountOutMin = 0 (as shown in test line 438), they will lose their input tokens entirely. This is particularly problematic for: 1. Tokens with high decimals where small amounts in wei terms could represent meaningful value 2. Users who don't understand the rounding behavior and set amountOutMin = 0 3. Automated systems or aggregators that may not properly validate minimum outputs
RECOMMENDATION
Add a check to revert when amountOut == 0 to prevent users from losing tokens without receiving anything in return. For example:

require(amountOut > 0, "Output amount is zero");
Alternatively, document this behavior clearly and ensure all integrations enforce a non-zero amountOutMin.
IMPACTED CODE

function _quoteExactIn(
    Strategy calldata strategy,
    uint256 balanceIn,
    uint256 balanceOut,
    uint256 amountIn
) internal view virtual returns (uint256 amountOut) {
    // Use constant product formula (x*y=const) after fee deduction:
    // balanceIn * balanceOut == (balanceIn + amountIn) * (balanceOut - amountOut)
    uint256 amountInWithFee = amountIn * (BPS_BASE - strategy.feeBps) / BPS_BASE;
    amountOut = (amountInWithFee * balanceOut) / (balanceIn + amountInWithFee);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/interfaces/IAqua.sol #L10-L98


examples/test/XYCNestedSwaps.t.sol #L1-L500


src/AquaApp.sol #L15-L44

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Arithmetic Issues: Division by Zero in quoteExactOut When amountOut Equals balanceOut

examples/apps/XYCSwap.sol

DESCRIPTION

The _quoteExactOut function calculates amountIn using the formula:

uint256 amountOutWithFee = amountOut * BPS_BASE / (BPS_BASE - strategy.feeBps);
amountIn = (balanceIn * amountOutWithFee).ceilDiv(balanceOut - amountOutWithFee);
When amountOutWithFee >= balanceOut, the denominator (balanceOut - amountOutWithFee) becomes zero or underflows. This can occur when: 1. A user requests amountOut equal to or close to balanceOut 2. The fee adjustment pushes amountOutWithFee to equal or exceed balanceOut For example, with balanceOut = 100, feeBps = 30 (0.3%), and amountOut = 100: - amountOutWithFee = 100 * 10000 / 9970 = 1003 (approximately) - balanceOut - amountOutWithFee would underflow This causes the transaction to revert with an arithmetic error rather than a descriptive error message, making it difficult for users and integrators to understand why their swap failed.
RECOMMENDATION
Add explicit validation to check that amountOutWithFee < balanceOut before performing the division, and revert with a descriptive error:

require(amountOutWithFee < balanceOut, "Insufficient liquidity for requested output");
IMPACTED CODE

function _quoteExactOut(
    Strategy calldata strategy,
    uint256 balanceIn,
    uint256 balanceOut,
    uint256 amountOut
) internal view virtual returns (uint256 amountIn) {
    // Use constant product formula (x*y=const) after fee deduction:
    // balanceIn * balanceOut == (balanceIn + amountIn) * (balanceOut - amountOut)
    uint256 amountOutWithFee = amountOut * BPS_BASE / (BPS_BASE - strategy.feeBps);
    amountIn = (balanceIn * amountOutWithFee).ceilDiv(balanceOut - amountOutWithFee);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/interfaces/IAqua.sol #L10-L98


examples/test/XYCNestedSwaps.t.sol #L1-L500


src/AquaApp.sol #L15-L44

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Unchecked Low-Level Calls: Arbitrary Delegatecall Allows Storage Manipulation

src/AquaRouter.sol

DESCRIPTION

The Simulator.simulate() function in AquaRouter allows any caller to execute a delegatecall to an arbitrary address with arbitrary data. Since delegatecall executes code in the context of the calling contract, a malicious actor can craft a call that modifies the AquaRouter contract's storage, including the _balances mapping. This could allow an attacker to: 1. Overwrite balance entries to steal funds from makers 2. Manipulate tokensCount values to bypass strategy validation 3. Set arbitrary balances for non-existent strategies The function is marked external payable with no access control, meaning anyone can call it. While the function always reverts with Simulated error, the delegatecall still executes and can modify storage before the revert. However, since the entire transaction reverts, the storage changes are not persisted. The function is designed for simulation purposes (view-like behavior via revert), but the pattern is risky if the contract is ever upgraded or if there are edge cases where the revert doesn't propagate correctly.
RECOMMENDATION
1. Add access control to restrict who can call simulate() 2. Consider using staticcall instead of delegatecall if only read operations are needed 3. Implement a whitelist of allowed delegatee addresses 4. Document clearly that this function is for off-chain simulation only and should never be called in a transaction that's expected to succeed
IMPACTED CODE

function simulate(address delegatee, bytes calldata data) external payable {
    (bool success, bytes memory result) = delegatee.delegatecall(data);
    revert Simulated(delegatee, data, success, result);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/libs/ReentrancyGuard.sol #L1-L60


src/libs/Simulator.sol #L1-L14


src/libs/Transient.sol #L1-L137

Show 13 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Logic & Business Rules: Pull Function Allows Draining Without Active Strategy Check

src/AquaRouter.sol

DESCRIPTION

The pull() function in Aqua.sol does not verify that the strategy is active (i.e., tokensCount > 0 && tokensCount != _DOCKED). This is in contrast to the push() function which explicitly checks require(tokensCount > 0 && tokensCount != _DOCKED, ...). This means: 1. An app (msg.sender) can call pull() on a docked strategy as long as there's remaining balance 2. After a maker docks their strategy, the app can still pull tokens if the balance wasn't fully depleted 3. The balance subtraction prevBalance - amount.toUint248() will succeed as long as there's sufficient balance While the dock() function sets balance to 0, if there's a race condition or if the maker docks before all pulls complete, the app could still pull from a strategy the maker intended to deactivate. However, this appears to be intentional design - apps should be able to complete pending operations even after dock. The real protection is that makers must approve tokens to the Aqua contract, and they can revoke that approval.
RECOMMENDATION
1. Document clearly that pull() intentionally works on docked strategies to allow completion of pending operations 2. Consider adding an optional flag to dock() that also revokes the app's ability to pull 3. Alternatively, add a check in pull() to verify the strategy is still active if stricter behavior is desired
IMPACTED CODE

function pull(address maker, bytes32 strategyHash, address token, uint256 amount, address to) external {
    Balance storage balance = _balances[maker][msg.sender][strategyHash][token];
    (uint248 prevBalance, uint8 tokensCount) = balance.load();
    balance.store(prevBalance - amount.toUint248(), tokensCount);

    IERC20(token).safeTransferFrom(maker, to, amount);
    emit Pulled(maker, msg.sender, strategyHash, token, amount);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/libs/ReentrancyGuard.sol #L1-L60


src/libs/Simulator.sol #L1-L14


src/libs/Transient.sol #L1-L137

Show 13 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Input Validation: Missing Array Length Validation in Ship Function

src/AquaRouter.sol

DESCRIPTION

The ship() function accepts two arrays tokens and amounts but does not validate that they have the same length. If amounts.length < tokens.length, the function will revert with an out-of-bounds error when accessing amounts[i]. If amounts.length > tokens.length, the extra amounts will be silently ignored. While this doesn't lead to fund loss (the transaction would revert or extra data is ignored), it represents poor input validation that could lead to user confusion or unexpected behavior.
RECOMMENDATION
Add explicit validation: require(tokens.length == amounts.length, "Array length mismatch");
IMPACTED CODE

function ship(address app, bytes calldata strategy, address[] calldata tokens, uint256[] calldata amounts) external returns(bytes32 strategyHash) {
    strategyHash = keccak256(strategy);
    uint8 tokensCount = tokens.length.toUint8();
    require(tokensCount != _DOCKED, MaxNumberOfTokensExceeded(tokensCount, _DOCKED));

    emit Shipped(msg.sender, app, strategyHash, strategy);
    for (uint256 i = 0; i < tokens.length; i++) {
        Balance storage balance = _balances[msg.sender][app][strategyHash][tokens[i]];
        require(balance.tokensCount == 0, StrategiesMustBeImmutable(app, strategyHash));
        balance.store(amounts[i].toUint248(), tokensCount);
        emit Pushed(msg.sender, app, strategyHash, tokens[i], amounts[i]);
    }
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/libs/ReentrancyGuard.sol #L1-L60


src/libs/Simulator.sol #L1-L14


src/libs/Transient.sol #L1-L137

Show 13 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Input Validation: Missing Array Length Validation in ship Function

src/Aqua.sol

DESCRIPTION

The ship function accepts two arrays tokens and amounts but does not validate that they have the same length. If amounts.length < tokens.length, the function will revert with an out-of-bounds error when accessing amounts[i] for i >= amounts.length. However, if amounts.length > tokens.length, the extra amounts will be silently ignored, potentially leading to user confusion or unexpected behavior where a maker believes they've set up a strategy with certain amounts but those amounts were never recorded.
RECOMMENDATION
Add explicit validation at the beginning of the ship function to ensure both arrays have the same length:

require(tokens.length == amounts.length, "Array length mismatch");
IMPACTED CODE

function ship(address app, bytes calldata strategy, address[] calldata tokens, uint256[] calldata amounts) external returns(bytes32 strategyHash) {
    strategyHash = keccak256(strategy);
    uint8 tokensCount = tokens.length.toUint8();
    require(tokensCount != _DOCKED, MaxNumberOfTokensExceeded(tokensCount, _DOCKED));

    emit Shipped(msg.sender, app, strategyHash, strategy);
    for (uint256 i = 0; i < tokens.length; i++) {
        Balance storage balance = _balances[msg.sender][app][strategyHash][tokens[i]];
        require(balance.tokensCount == 0, StrategiesMustBeImmutable(app, strategyHash));
        balance.store(amounts[i].toUint248(), tokensCount);
        emit Pushed(msg.sender, app, strategyHash, tokens[i], amounts[i]);
    }
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaRouter.sol #L1-L15


test/Aqua.t.sol #L124-L485


src/libs/Balance.sol #L7-L10

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Input Validation: Duplicate Tokens in ship Allow Balance Overwrite

src/Aqua.sol

DESCRIPTION

The ship function does not validate that the tokens array contains unique addresses. If a maker calls ship with duplicate token addresses (e.g., [tokenA, tokenA]), the second occurrence will overwrite the balance set by the first occurrence. The check require(balance.tokensCount == 0, StrategiesMustBeImmutable(app, strategyHash)) only prevents re-shipping an already shipped strategy, but within the same ship call, the first iteration sets tokensCount to a non-zero value, and the second iteration will fail this check. However, if the duplicate token appears at different positions with different amounts, the first write sets tokensCount to tokens.length, and the second iteration will revert because tokensCount != 0. This is actually a protection, but the error message StrategiesMustBeImmutable is misleading in this context as it suggests the strategy was already shipped rather than indicating duplicate tokens.
RECOMMENDATION
Add explicit validation to check for duplicate tokens in the array and provide a clearer error message:

error DuplicateTokenInStrategy(address token);

// In ship function, before the loop:
for (uint256 i = 0; i < tokens.length; i++) {
    for (uint256 j = i + 1; j < tokens.length; j++) {
        require(tokens[i] != tokens[j], DuplicateTokenInStrategy(tokens[i]));
    }
}
Alternatively, use a more descriptive error for this case.
IMPACTED CODE

for (uint256 i = 0; i < tokens.length; i++) {
    Balance storage balance = _balances[msg.sender][app][strategyHash][tokens[i]];
    require(balance.tokensCount == 0, StrategiesMustBeImmutable(app, strategyHash));
    balance.store(amounts[i].toUint248(), tokensCount);
    emit Pushed(msg.sender, app, strategyHash, tokens[i], amounts[i]);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaRouter.sol #L1-L15


test/Aqua.t.sol #L124-L485


src/libs/Balance.sol #L7-L10

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


LOW
Logic & Business Rules: Pull Function Allows Draining Without Active Strategy Check

src/Aqua.sol

DESCRIPTION

The pull function does not verify that the strategy is active (i.e., tokensCount > 0 && tokensCount != _DOCKED). While the push function explicitly checks this condition, pull only performs arithmetic on the balance without validating the strategy state. This means: 1. An app can call pull on a docked strategy if there's somehow a non-zero balance (though dock sets balance to 0) 2. An app can call pull on a strategy that was never shipped for that token, as long as the arithmetic doesn't underflow The protection relies on the arithmetic underflow when prevBalance < amount, but this is implicit rather than explicit. For a strategy that was never shipped, tokensCount would be 0, and the pull would still succeed if amount is 0 (edge case).
RECOMMENDATION
Add an explicit check in the pull function to ensure the strategy is active:

function pull(address maker, bytes32 strategyHash, address token, uint256 amount, address to) external {
    Balance storage balance = _balances[maker][msg.sender][strategyHash][token];
    (uint248 prevBalance, uint8 tokensCount) = balance.load();
    require(tokensCount > 0 && tokensCount != _DOCKED, "Strategy not active");
    balance.store(prevBalance - amount.toUint248(), tokensCount);
    // ...
}
IMPACTED CODE

function pull(address maker, bytes32 strategyHash, address token, uint256 amount, address to) external {
    Balance storage balance = _balances[maker][msg.sender][strategyHash][token];
    (uint248 prevBalance, uint8 tokensCount) = balance.load();
    balance.store(prevBalance - amount.toUint248(), tokensCount);

    IERC20(token).safeTransferFrom(maker, to, amount);
    emit Pulled(maker, msg.sender, strategyHash, token, amount);
}
CONTEXT USED

Resources accessed by the model to generate this finding

src/AquaRouter.sol #L1-L15


test/Aqua.t.sol #L124-L485


src/libs/Balance.sol #L7-L10

Show 19 more




Generate Fix

Generate POC
Beta

Dismiss


Resolve


Severity


INFO
Input Validation: Multicall Not Payable Prevents ETH Forwarding

src/libs/Multicall.sol

DESCRIPTION

The multicall function is not marked as payable, which means it cannot receive ETH. However, the Simulator.simulate() function in the same inheritance chain is marked as payable. If a user wants to batch calls that include simulate() with ETH value, they cannot do so through multicall because the function will revert when receiving ETH. This is a design limitation rather than a critical vulnerability, but it restricts the functionality of the multicall pattern when ETH needs to be forwarded to payable functions.
RECOMMENDATION
If ETH forwarding is intended to be supported, mark the multicall function as payable. Note that this would require careful handling of msg.value to prevent double-spending across multiple calls in the batch.
IMPACTED CODE

function multicall(bytes[] calldata data) external {
CONTEXT USED

Resources accessed by the model to generate this finding

src/libs/TransientLock.sol #L1-L37


src/libs/ReentrancyGuard.sol #L1-L60


src/libs/Simulator.sol #L1-L18