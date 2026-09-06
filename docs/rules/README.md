# Security Rules

Pinocchio Sentinel implements 14 security rules for Solana programs. Each rule detects a specific class of vulnerability that Anchor prevents structurally but that raw Solana programs must handle manually.

## Rule Summary

| Rule | Category | Severity | Confidence |
|------|----------|----------|------------|
| PS-001 | Account Validation | HIGH | Medium |
| PS-002 | Account Validation | HIGH | Medium |
| PS-003 | Account Validation | HIGH | Medium |
| PS-004 | Data Safety | HIGH | Medium |
| PS-005 | PDA Security | MEDIUM | Low |
| PS-006 | Account Uniqueness | MEDIUM | Low |
| PS-007 | CPI Security | HIGH | Low |
| PS-008 | Account Lifecycle | HIGH | Medium |
| PS-009 | Account Lifecycle | HIGH | Medium |
| PS-010 | Account Validation | HIGH | Medium |
| PS-011 | CPI Security | HIGH | Medium |
| PS-012 | Data Safety | WARN | Medium |
| PS-013 | CPI Security | HIGH | Medium |
| PS-014 | Sysvar Security | HIGH | Medium |

---

## Account Validation Rules

### PS-001: Missing Signer Check

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Authority account used without `is_signer()` assertion

**Vulnerable pattern:**
```rust
let authority = &accounts[0];
// Uses authority without checking is_signer()
let data = authority.try_borrow_data()?;
```

**Secure pattern:**
```rust
let authority = &accounts[0];
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
let data = authority.try_borrow_data()?;
```

**Exploit scenario:**
1. Attacker creates a keypair
2. Passes the public key as the authority account
3. Does NOT sign the transaction
4. Program proceeds as if the authority is valid

---

### PS-002: Missing Owner Check

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Account data read without `owned_by(&crate::ID)` check

**Vulnerable pattern:**
```rust
let vault = &accounts[1];
let data = vault.try_borrow_data()?;
```

**Secure pattern:**
```rust
let vault = &accounts[1];
if !vault.owned_by(&crate::ID) {
    return Err(ProgramError::IncorrectProgramId);
}
let data = vault.try_borrow_data()?;
```

**Exploit scenario:**
1. Attacker creates account owned by System Program
2. Writes matching data structure
3. Program reads fake account as legitimate

---

### PS-003: Missing Discriminant Check

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Account cast without verifying discriminator bytes

**Vulnerable pattern:**
```rust
let data = account.try_borrow_data()?;
let vault = VaultAccount::try_from_slice(&data)?;
```

**Secure pattern:**
```rust
let data = account.try_borrow_data()?;
if &data[0..8] != &VaultAccount::DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
let vault = VaultAccount::try_from_slice(&data)?;
```

---

### PS-010: Missing Writable Check

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Account mutated without `is_writable()` assertion

**Vulnerable pattern:**
```rust
let vault = &accounts[0];
**vault.try_borrow_mut_lamports()? += 1;
```

**Secure pattern:**
```rust
let vault = &accounts[0];
if !vault.is_writable() {
    return Err(ProgramError::InvalidAccountData);
}
**vault.try_borrow_mut_lamports()? += 1;
```

---

## Data Safety Rules

### PS-004: Missing Bounds Check

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Zero-copy cast without `data_len()` bounds assertion

**Vulnerable pattern:**
```rust
let data = account.try_borrow_data()?;
let vault = bytemuck::from_bytes(&data);
```

**Secure pattern:**
```rust
let data = account.try_borrow_data()?;
if data.len() < std::mem::size_of::<VaultAccount>() {
    return Err(ProgramError::InvalidAccountData);
}
let vault = bytemuck::from_bytes(&data);
```

---

### PS-012: Slice Index Without Bounds

**Severity:** WARN  
**Confidence:** Medium  
**What it catches:** Array access without length verification

**Vulnerable pattern:**
```rust
let amount = u64::from_le_bytes(data[1..9].try_into()?);
```

**Secure pattern:**
```rust
if data.len() < 9 {
    return Err(ProgramError::InvalidInstructionData);
}
let amount = u64::from_le_bytes(data[1..9].try_into()?);
```

---

## PDA Security Rules

### PS-005: PDA Without Canonical Bump

**Severity:** MEDIUM  
**Confidence:** Low  
**What it catches:** PDA used without verifying canonical bump seed

**Vulnerable pattern:**
```rust
let (pda, _bump) = Pubkey::find_program_address(&[b"vault"], &crate::ID);
// No bump verification
```

**Secure pattern:**
```rust
let (pda, canonical_bump) = Pubkey::find_program_address(&[b"vault"], &crate::ID);
assert_eq!(bump, canonical_bump);
```

---

## Account Uniqueness Rules

### PS-006: Account Aliasing

**Severity:** MEDIUM  
**Confidence:** Low  
**What it catches:** Two mutable account references that may point to the same account

**Vulnerable pattern:**
```rust
let source = &accounts[0];
let dest = &accounts[1];
// No uniqueness check
source.try_borrow_mut_lamports()?;
dest.try_borrow_mut_lamports()?;
```

**Secure pattern:**
```rust
let source = &accounts[0];
let dest = &accounts[1];
if source.key() == dest.key() {
    return Err(ProgramError::InvalidArgument);
}
```

---

## CPI Security Rules

### PS-007: Arbitrary CPI Target

**Severity:** HIGH  
**Confidence:** Low  
**What it catches:** CPI to unverified program ID

**Vulnerable pattern:**
```rust
let target_program = &accounts[2];
invoke(&instruction, &[target_program.clone()], &[])?;
```

**Secure pattern:**
```rust
let target_program = &accounts[2];
if target_program.key() != &expected_program_id {
    return Err(ProgramError::IncorrectProgramId);
}
invoke(&instruction, &[target_program.clone()], &[])?;
```

---

### PS-011: Missing Account Count Gate

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** `lazy_program_entrypoint!` used without checking `accounts.len()`

**Vulnerable pattern:**
```rust
lazy_program_entrypoint!(process_instruction);
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), ProgramError> {
    let vault = &accounts[0]; // No len check
}
```

**Secure pattern:**
```rust
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), ProgramError> {
    if accounts.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let vault = &accounts[0];
}
```

---

### PS-013: Unchecked CPI Return

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** CPI return value not checked

**Vulnerable pattern:**
```rust
let _ = invoke(&instruction, &accounts, &[]);
// Program continues as if CPI succeeded
```

**Secure pattern:**
```rust
invoke(&instruction, &accounts, &[])?;
// Program only continues if CPI succeeded
```

---

## Account Lifecycle Rules

### PS-008: Account Reinitialization

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Init path reachable on already-initialized account

**Vulnerable pattern:**
```rust
let vault = &accounts[0];
vault_data.authority = new_authority;
```

**Secure pattern:**
```rust
let vault = &accounts[0];
if vault_data.initialized {
    return Err(ProgramError::AccountAlreadyInitialized);
}
vault_data.initialized = true;
vault_data.authority = new_authority;
```

---

### PS-009: Lamport Zeroing Missing

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Lamport reduction without data zeroing

**Vulnerable pattern:**
```rust
**vault.try_borrow_mut_lamports()? -= amount;
```

**Secure pattern:**
```rust
**vault.try_borrow_mut_lamports()? -= amount;
vault_data.data.iter_mut().for_each(|b| *b = 0);
```

---

## Sysvar Security Rules

### PS-014: Sysvar Without Pubkey Check

**Severity:** HIGH  
**Confidence:** Medium  
**What it catches:** Sysvar account used without verifying its public key

**Vulnerable pattern:**
```rust
let clock = &accounts[3];
let clock_data = Clock::from_account_info(clock)?;
```

**Secure pattern:**
```rust
let clock = &accounts[3];
if clock.key() != &clock::ID {
    return Err(ProgramError::InvalidArgument);
}
let clock_data = Clock::from_account_info(clock)?;
```

---

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **HIGH** | Critical security vulnerability | Must fix before deployment |
| **MEDIUM** | Security concern | Should fix, may be acceptable in some contexts |
| **WARN** | Code quality issue | Recommended to fix |
| **LOW** | Minor issue | Consider fixing |
| **INFO** | Informational | No action required |

## Confidence Levels

| Level | Description |
|-------|-------------|
| **High** | High confidence, low false positive rate |
| **Medium** | Medium confidence, some false positives possible |
| **Low** | Low confidence, likely false positive |

## Extending Rules

To add a new rule:

1. Create `src/rules/ps0XX.rs`
2. Implement the `Rule` trait:

```rust
use super::{Rule, Finding, Severity, Confidence};
use crate::graph::AccountAccessGraph;

pub struct Ps0XX;

impl Rule for Ps0XX {
    fn id(&self) -> &str { "PS-0XX" }
    fn description(&self) -> &str { "Description of the rule" }
    fn severity(&self) -> Severity { Severity::HIGH }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        // Rule logic here
        vec![]
    }
}
```

3. Register in `src/rules/mod.rs`
4. Add to `src/config/mod.rs` default enabled rules
5. Add exploit generator in `src/evidence/generator.rs`
6. Add SARIF metadata in `src/output/sarif.rs`
7. Add tests

## References

- [Solana Security Checklist](https://docs.solana.com/security)
- [Anchor Security](https://docs.anchor-lang.com/docs/security)
- [Pinocchio](https://github.com/anza-xyz/pinocchio)
- [solana-security-examples](https://github.com/mira4sol/solana-security-examples)
