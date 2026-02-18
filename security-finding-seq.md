# Nado Contracts Security Audit Findings

**Audit Date:** February 18, 2026  
**Document:** security-finding-seq.md  
**Total Findings:** 3 (2 HIGH, 1 MEDIUM)

---

## Table of Contents

1. [HIGH Severity Findings](#high-severity-findings)
   - [Finding 1: Sequencer Can Submit Transactions Without Signature Verification](#finding-1-sequencer-can-submit-transactions-without-signature-verification)
   - [Finding 2: Health Check Always Returns True](#finding-2-health-check-always-returns-true-allowing-unhealthy-trades)
2. [MEDIUM Severity Findings](#medium-severity-findings)
   - [Finding 3: Division by Zero in Socialization](#finding-3-division-by-zero-in-socialization-when-open-interest-is-zero)

---

## HIGH SEVERITY FINDINGS

### Finding 1: Sequencer Can Submit Transactions Without Signature Verification

**Finding ID:** abaa7dde-9f10-4ef3-b518-a4feae56a6b0  
**File:** `core/contracts/Endpoint.sol`  
**Severity:** HIGH  
**Status:** Open  
**Created:** December 12, 2025, 3:08 PM

#### Title
Sequencer Can Submit Transactions Without Signature Verification

#### Description
The `submitTransactionsCheckedWithGasLimit` function at lines 793-809 allows the sequencer to submit and process transactions without any signature verification. 

Unlike `submitTransactionsChecked` which validates a Schnorr signature via `verifier.requireValidSignature()`, this function only validates the submission index and then processes all transactions directly. 

This means the sequencer can unilaterally execute any transaction type including:
- Price updates
- Order matching
- State changes
- Other critical operations

All of these can occur without cryptographic proof of authorization from the signing committee.

#### Security Impact
- **Authorization Bypass:** Critical transactions bypass signature verification
- **Unilateral Execution:** Sequencer can execute any transaction without committee approval
- **State Manipulation:** Unauthorized state changes possible
- **Price Manipulation:** Price updates without verification
- **Loss of Consensus:** Breaks the intended cryptographic guarantees of the system

#### Impacted Code
```solidity
function submitTransactionsCheckedWithGasLimit(
    uint64 idx,
    bytes[] calldata transactions,
    uint256 gasLimit
) external {
    uint256 initialGas = gasleft();
    validateSubmissionIdx(idx);
    for (uint256 i = 0; i < transactions.length; i++) {
        bytes calldata transaction = transactions[i];
        processTransaction(transaction);
        uint256 gasUsed = initialGas - gasleft();
        if (gasUsed > gasLimit) {
            verifier.revertGasInfo(i, gasUsed);
        }
    }
    verifier.revertGasInfo(transactions.length, initialGas - gasleft());
}
```

#### Comparison with Secure Implementation
The `submitTransactionsChecked` function (referenced for comparison) includes proper signature verification:

```solidity
function submitTransactionsChecked(
    uint64 idx,
    bytes[] calldata transactions,
    // ... signature parameters
) external {
    verifier.requireValidSignature(/* signature validation */);  // ← Missing in WithGasLimit variant
    validateSubmissionIdx(idx);
    for (uint256 i = 0; i < transactions.length; i++) {
        bytes calldata transaction = transactions[i];
        processTransaction(transaction);
    }
}
```

#### Recommendation

Choose one of the following approaches:

**Option 1: Add Signature Verification (RECOMMENDED)**
```solidity
function submitTransactionsCheckedWithGasLimit(
    uint64 idx,
    bytes[] calldata transactions,
    uint256 gasLimit,
    bytes calldata signature,  // Add signature parameter
    bytes32 signatureRoot      // Add root parameter
) external {
    // Add the missing signature verification
    verifier.requireValidSignature(idx, transactions, signature, signatureRoot);
    
    uint256 initialGas = gasleft();
    validateSubmissionIdx(idx);
    for (uint256 i = 0; i < transactions.length; i++) {
