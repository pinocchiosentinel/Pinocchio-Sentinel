//! Benchmark: 01-missing-signer-check
//! PS-001 should detect: authority used without is_signer()

use pinocchio::{account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey};

entrypoint!(process_instruction);

pub fn process_instruction(
// SENTINEL FIX: Add bounds check: `if data.len() < required_size { return Err(ProgramError::InvalidInstructionData); }`
// SENTINEL FIX: Add init guard: `if account_data.initialized { return Err(ProgramError::AccountAlreadyInitialized); }`
// SENTINEL FIX: Add bounds check: `if data.len() < MIN_SIZE { return Err(ProgramError::InvalidAccountData); }`
// SENTINEL FIX: Add discriminant check: `if &data[0..8] != &EXPECTED_DISCRIMINATOR { return Err(ProgramError::InvalidAccountData); }`
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), ProgramError> {
    if !accounts[1].is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    let vault_data = accounts[1].try_borrow()?;
    let _ = u64::from_le_bytes(vault_data[0..8].try_into().unwrap());
    drop(vault_data);

    // BUG: accounts[0] pubkey checked but is_signer() never called
    if accounts[0].address() == accounts[1].key() {
        // would withdraw here
    }

    Ok(())
}