# Security Rules

Pinocchio Sentinel implements 14 security rules for Solana programs.

## Rule Categories

### Account Validation (PS-001, PS-002, PS-003, PS-010)

- **PS-001**: Authority account used without `is_signer()` assertion
- **PS-002**: Account data read without `owned_by(&crate::ID)`
- **PS-003**: Account cast without discriminant check
- **PS-010**: Account mutated without `is_writable()` assertion

### Data Safety (PS-004, PS-012)

- **PS-004**: Zero-copy cast without `data_len()` bounds assertion
- **PS-012**: Slice index accessed without length assertion

### PDA Security (PS-005)

- **PS-005**: PDA used without canonical bump verification

### Account Uniqueness (PS-006)

- **PS-006**: Two account indices may alias, both mutated

### CPI Security (PS-007, PS-011, PS-013)

- **PS-007**: CPI target program ID not compared against constant
- **PS-011**: `lazy_program_entrypoint!` without account-count gate
- **PS-013**: CPI return value not checked

### Account Lifecycle (PS-008, PS-009)

- **PS-008**: Initialization path reachable on already-initialized account
- **PS-009**: Lamport reduction without data zeroing

### Sysvar Security (PS-014)

- **PS-014**: Sysvar account without pubkey comparison

## Detailed Rule Documentation

### PS-001: Missing Signer Check

**Severity**: HIGH

Authority account used without `is_signer()` assertion.

**Vulnerable Pattern**:
```rust
let authority = &accounts[0];
// No is_signer() check
let data = authority.try_borrow()?;
```

**Secure Pattern**:
```rust
let authority = &accounts[0];
if !authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
let data = authority.try_borrow()?;
```

**Exploit Scenario**:
1. Attacker creates a keypair
2. Attacker passes the public key as the authority account
3. Attacker does NOT sign the transaction
4. Program proceeds as if the authority is valid
5. Attacker gains unauthorized access

---

### PS-002: Missing Owner Check

**Severity**: HIGH

Account data read without `owned_by(&crate::ID)`.

**Vulnerable Pattern**:
```rust
let vault = &accounts[1];
// No owned_by() check
let data = vault.try_borrow()?;
```

**Secure Pattern**:
```rust
let vault = &accounts[1];
if !vault.owned_by(&crate::ID) {
    return Err(ProgramError::IncorrectProgramId);
}
let data = vault.try_borrow()?;
```

**Exploit Scenario**:
1. Attacker creates account owned by System Program
2. Attacker writes matching data structure
3. Program reads fake account as legitimate
4. Attacker gains unauthorized access to funds

---

### PS-003: Missing Discriminant Check

**Severity**: HIGH

Account cast without discriminant check.

**Vulnerable Pattern**:
```rust
let data = account.try_borrow()?;
let vault = VaultAccount::try_from_slice(&data)?;
```

**Secure Pattern**:
```rust
let data = account.try_borrow()?;
if &data[0..8] != &VaultAccount::DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
let vault = VaultAccount::try_from_slice(&data)?;
```

**Exploit Scenario**:
1. Attacker creates account with wrong type but valid data layout
2. Program misinterprets account type
3. Attacker gains unauthorized access

---

### PS-004: Missing Bounds Check

**Severity**: HIGH

Zero-copy cast without `data_len()` bounds assertion.

**Vulnerable Pattern**:
```rust
let data = account.try_borrow()?;
let vault = bytemuck::from_bytes(&data);
```

**Secure Pattern**:
```rust
let data = account.try_borrow()?;
if data.len() < std::mem::size_of::<VaultAccount>() {
    return Err(ProgramError::InvalidAccountData);
}
let vault = bytemuck::from_bytes(&data);
```

**Exploit Scenario**:
1. Attacker provides account with insufficient data
2. Program casts data to struct
3. Program reads uninitialized memory

---

### PS-005: PDA Without Canonical Bump

**Severity**: MEDIUM

PDA used without canonical bump verification.

**Vulnerable Pattern**:
```rust
let (pda, _bump) = Pubkey::find_program_address(&[b"vault"], &crate::ID);
// No bump verification
```

**Secure Pattern**:
```rust
let (pda, canonical_bump) = Pubkey::find_program_address(&[b"vault"], &crate::ID);
assert_eq!(bump, canonical_bump);
```

**Exploit Scenario**:
1. Attacker derives PDA with non-canonical bump
2. PDA passes seed check but bump isn't canonical
3. Attacker gains control of PDA

---

### PS-006: Account Aliasing

**Severity**: MEDIUM

Two account indices may alias, both mutated.

**Vulnerable Pattern**:
```rust
let source = &accounts[0];
let dest = &accounts[1];
// No uniqueness check
source.try_borrow_mut_lamports()?;
dest.try_borrow_mut_lamports()?;
```

**Secure Pattern**:
```rust
let source = &accounts[0];
let dest = &accounts[1];
if source.key() == dest.key() {
    return Err(ProgramError::InvalidArgument);
}
```

**Exploit Scenario**:
1. Attacker passes same account as source and dest
2. Balance double-counted or overwritten
3. Funds stolen

---

### PS-007: Arbitrary CPI

**Severity**: HIGH

CPI target program ID not compared against constant.

**Vulnerable Pattern**:
```rust
let target_program = &accounts[2];
// No program ID check
invoke(&instruction, &[target_program.clone()], &[])?;
```

**Secure Pattern**:
```rust
let target_program = &accounts[2];
if target_program.key() != &expected_program_id {
    return Err(ProgramError::IncorrectProgramId);
}
invoke(&instruction, &[target_program.clone()], &[])?;
```

**Exploit Scenario**:
1. Attacker passes malicious program as CPI target
2. CPI executes attacker's code
3. Funds stolen

---

### PS-008: Account Reinitialization

**Severity**: HIGH

Initialization path reachable on already-initialized account.

**Vulnerable Pattern**:
```rust
let vault = &accounts[0];
// No init guard
vault_data.authority = new_authority;
```

**Secure Pattern**:
```rust
let vault = &accounts[0];
if vault_data.initialized {
    return Err(ProgramError::AccountAlreadyInitialized);
}
vault_data.initialized = true;
vault_data.authority = new_authority;
```

**Exploit Scenario**:
1. Attacker calls init instruction on already-initialized account
2. Vault authority overwritten
3. Funds stolen

---

### PS-009: Lamport Zeroing Missing

**Severity**: HIGH

Lamport reduction without data zeroing.

**Vulnerable Pattern**:
```rust
**vault.try_borrow_mut_lamports()? -= amount;
```

**Secure Pattern**:
```rust
**vault.try_borrow_mut_lamports()? -= amount;
vault_data.data.iter_mut().for_each(|b| *b = 0);
```

**Exploit Scenario**:
1. Attacker reduces lamports without clearing data
2. Account retains data with reduced rent
3. Ghost account attack possible

---

### PS-010: Missing Writable Check

**Severity**: HIGH

Account mutated without `is_writable()` assertion.

**Vulnerable Pattern**:
```rust
let vault = &accounts[0];
// No is_writable() check
**vault.try_borrow_mut_lamports()? += 1;
```

**Secure Pattern**:
```rust
let vault = &accounts[0];
if !vault.is_writable() {
    return Err(ProgramError::InvalidAccountData);
}
**vault.try_borrow_mut_lamports()? += 1;
```

**Exploit Scenario**:
1. Attacker passes read-only account as mutable
2. Write silently fails or causes undefined behavior

---

### PS-011: Missing Account Count Gate

**Severity**: HIGH

`lazy_program_entrypoint!` invoked without account-count gate.

**Vulnerable Pattern**:
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

**Secure Pattern**:
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

**Exploit Scenario**:
1. Attacker passes fewer accounts than expected
2. Program panics with index out of bounds

---

### PS-012: Slice Index Without Bounds

**Severity**: WARN

Slice index accessed without length assertion.

**Vulnerable Pattern**:
```rust
let data = instruction_data;
let amount = u64::from_le_bytes(data[1..9].try_into()?);
```

**Secure Pattern**:
```rust
let data = instruction_data;
if data.len() < 9 {
    return Err(ProgramError::InvalidInstructionData);
}
let amount = u64::from_le_bytes(data[1..9].try_into()?);
```

**Exploit Scenario**:
1. Attacker provides short instruction data
2. Program panics with index out of bounds

---

### PS-013: Unchecked CPI Return

**Severity**: HIGH

CPI return value not checked.

**Vulnerable Pattern**:
```rust
let _ = invoke(&instruction, &accounts, &[]);
// Program continues as if CPI succeeded
```

**Secure Pattern**:
```rust
invoke(&instruction, &accounts, &[])?;
// Program only continues if CPI succeeded
```

**Exploit Scenario**:
1. CPI fails silently
2. Program continues as if succeeded
3. State inconsistency, double-spend possible

---

### PS-014: Sysvar Without Pubkey Check

**Severity**: HIGH

Sysvar account without pubkey comparison.

**Vulnerable Pattern**:
```rust
let clock = &accounts[3];
// No pubkey check
let clock_data = Clock::from_account_info(clock)?;
```

**Secure Pattern**:
```rust
let clock = &accounts[3];
if clock.key() != &clock::ID {
    return Err(ProgramError::InvalidArgument);
}
let clock_data = Clock::from_account_info(clock)?;
```

**Exploit Scenario**:
1. Attacker passes fake clock sysvar
2. Time manipulated for flash loan attacks

---

## Severity Levels

- **HIGH**: Critical security vulnerability, likely exploitable
- **MEDIUM**: Security concern, potentially exploitable
- **WARN**: Code quality issue, potential security risk
- **LOW**: Minor issue, unlikely to be exploitable
- **INFO**: Informational finding

## Confidence Levels

- **High**: High confidence in the finding
- **Medium**: Medium confidence, may have false positives
- **Low**: Low confidence, likely false positive
