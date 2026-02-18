# Snowbridge Security Audit Findings

**Audit Date:** 2026-02-18  
**Prepared by:** Security Audit Team

---

## Executive Summary

This document contains 12 security findings across the Snowbridge codebase, including 2 **CRITICAL**, 4 **HIGH**, 4 **MEDIUM**, and 2 **LOW** severity issues. The findings span both Solidity smart contracts and Go relayer code, with critical vulnerabilities in initialization guards, concurrency control, and access management.

---

## Table of Contents

1. [CRITICAL Findings](#critical-findings)
2. [HIGH Findings](#high-findings)
3. [MEDIUM Findings](#medium-findings)
4. [LOW Findings](#low-findings)

---

## CRITICAL Findings

### Finding 1: Unrestricted and Re-runnable initialize() Allows Full Storage Takeover

**Finding ID:** 7199d528-d5f8-4b3c-9eec-95ba423a063e  
**File:** `contracts/src/Initializer.sol`  
**Severity:** CRITICAL  
**Status:** Open

#### Title
Unrestricted and Re-runnable initialize() allows full storage takeover

#### Description
The `Initializer.initialize` function is public and lacks any reinitialization guard or access control. After the first call (which only checks that the implementation slot is non-zero), anyone can call initialize again via the proxy and overwrite critical protocol configuration (agents, channels, fees, exchange rates, etc). This results in a complete takeover of the bridge configuration and asset parameters.

#### Impact
- Complete takeover of bridge configuration
- Arbitrary reconfiguration of critical protocol parameters
- Loss of asset control and fund security

#### Impacted Code
```solidity
function initialize(bytes calldata data) external {
    // Prevent initialization of storage in implementation contract
    if (ERC1967.load() == address(0)) {
        revert Unauthorized();
    }

    CoreStorage.Layout storage core = CoreStorage.layout();
    
    Config memory config = abi.decode(data, (Config));
    
    core.mode = config.mode;
    ...
}
```

#### Recommendation
Implement a one-time initializer guard or restrict initialize() to the proxy admin or a dedicated owner role. Options include:

1. **Use OpenZeppelin's Initializable Pattern:** Leverage `initializer` and `reinitializer` modifiers
2. **Add Boolean Guard:** Implement an `initialized` boolean flag that reverts if initialize is called more than once
3. **Add Access Control:** Restrict to `onlyOwner` or `onlyProxyAdmin` modifier
4. **Version-Based Guard:** Check a stored version number before proceeding

#### References
- `contracts/src/storage/PricingStorage.sol` #L1-L200
- `contracts/src/utils/ERC1967.sol` #L1-L200
- `contracts/src/storage/CoreStorage.sol` #L1-L200

---

### Finding 2: Data Race in ErrorTracker Without Concurrency Protection

**Finding ID:** 074dc752-d248-4a9b-abc8-b9f75056d6be  
**File:** `relayer/relays/error_tracking/tracker.go`  
**Severity:** CRITICAL (appears as HIGH in listing but impacts critical relayer safety)  
**Status:** Open

#### Title
Data Race in ErrorTracker Without Concurrency Protection

#### Description
The `ErrorTracker` uses internal mutable state (`transientErrors`, `permanentErrors`, `totalAttempts`, `lastResetTime`, `consecutiveErrors`) that is updated from multiple methods without any synchronization:
- `RecordSuccess()`
- `RecordTransientError()`
- `RecordPermanentError()`
- `checkAndResetCounters()`
- `checkForAlerts()`

In the relayer execution code, a single `ErrorTracker` instance is attached to the Relay struct and may be invoked concurrently by multiple goroutines handling events and retries. This can lead to:
- Data races and undefined behavior
- Inaccurate error metrics
- Missed alert triggers
- Corrupted state

#### Impact
- Relayer crashes due to concurrent map/slice access panics
- Incorrect error tracking and reporting
- Missed critical alerts for fatal conditions
- Unpredictable relayer behavior under load

#### Impacted Code
```go
type ErrorTracker struct {
    transientErrors   int
    permanentErrors   int
    totalAttempts     int
    lastResetTime     time.Time
    consecutiveErrors int
    maxConsecutive    int
}

func (et *ErrorTracker) RecordTransientError() {
    et.totalAttempts++
    et.transientErrors++
    et.consecutiveErrors++
    et.checkAndResetCounters()
    et.checkForAlerts()
}

func (et *ErrorTracker) RecordSuccess() {
    et.totalAttempts++
    et.consecutiveErrors = 0
    et.checkAndResetCounters()
}

func (et *ErrorTracker) RecordPermanentError() {
    et.totalAttempts++
    et.permanentErrors++
    et.consecutiveErrors = 0
    et.checkAndResetCounters()
}
```

#### Recommendation
Protect shared state in `ErrorTracker` using one of the following approaches:

1. **Mutex Protection (Recommended):** Embed a `sync.Mutex` or `sync.RWMutex` and lock around all updates and reads
   ```go
   type ErrorTracker struct {
       mu                sync.RWMutex
       transientErrors   int
       permanentErrors   int
       totalAttempts     int
       lastResetTime     time.Time
       consecutiveErrors int
       maxConsecutive    int
   }
   
   func (et *ErrorTracker) RecordTransientError() {
       et.mu.Lock()
       defer et.mu.Unlock()
       // ... perform updates
   }
   ```

2. **Channel-Based Serialization:** Serialize all calls to the tracker on a single goroutine using channels

3. **Atomic Operations:** Use `sync/atomic` for individual counters if applicable

#### References
- `relayer/relays/execution/main.go` #L1-L200, #L1-L100, #L190-L350

---

## HIGH Findings

### Finding 3: Missing Access Control on Upgrade Function

**Finding ID:** a155578a-e9d2-444b-9fd4-59fc0b7b7255  
**File:** `contracts/src/Upgrade.sol`  
**Severity:** HIGH  
**Status:** Open

#### Title
Missing Access Control on Upgrade Function

#### Description
The `upgrade` function in `contracts/src/Upgrade.sol` is exposed via external library call and lacks any access control checks. This allows any caller with access to the proxy's `v1_handleUpgrade` or `v2_handleUpgrade` (which themselves are protected by `onlySelf` but rely on cross-chain governance messages) to trigger an upgrade to an arbitrary implementation with provided `initializerParams`.

If the protection on `onlySelf` or cross-chain message dispatch is misconfigured or bypassed, an attacker could upgrade the contract to a malicious implementation.

#### Impact
- Unauthorized contract upgrades
- Malicious implementation injection
- Complete loss of contract functionality
- Potential theft of user funds

#### Impacted Code
```solidity
function upgrade(address impl, bytes32 implCodeHash, bytes memory initializerParams)
    external
{
    // Verify that the implementation is actually a contract
    if (!impl.isContract()) {
        revert IUpgradable.InvalidContract();
    }

    // As a sanity check, ensure that the codehash of implementation contract
    // matches the codehash in the upgrade proposal
    if (impl.codehash != implCodeHash) {
        revert IUpgradable.InvalidCodeHash();
    }

    // Update the proxy with the address of the new implementation
    ERC1967.store(impl);

    // Call the initializer
    (bool success, bytes memory returndata) =
        impl.delegatecall(abi.encodeCall(IInitializable.initialize, initializerParams));
    Call.verifyResult(success, returndata);

    emit IUpgradable.Upgraded(impl);
}
```

#### Recommendation
Ensure that only the intended governance mechanism (e.g., Polkadot cross-chain message handler) can invoke the upgrade. Add explicit access control checks:

1. **Add Access Control Modifier:** Use `onlyOwner`, `onlyRole(UPGRADER_ROLE)`, or similar
2. **Verify Cross-Chain Origin:** Explicitly verify cross-chain message origin at entry points (`v1_handleUpgrade` and `v2_handleUpgrade`)
3. **Whitelist Implementation Addresses:** Maintain a whitelist of approved implementation addresses
4. **Time-Lock:** Consider implementing a time-lock pattern for upgrades

#### References
- `contracts/src/Gateway.sol` #L330-L350, #L300-L400
- `contracts/src/v1/Handlers.sol` #L1-L200
- `contracts/src/v2/Handlers.sol` #L1-L200

---

### Finding 4: Missing Initializer Guard Allows Re-initialization and State Overwrite

**Finding ID:** 7144b79f-cedc-46ba-bf9a-522f889eb441
