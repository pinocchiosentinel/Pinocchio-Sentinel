//! Benchmark: 03-account-data-matching
//! PS-003 should detect: account cast without discriminant check

use pinocchio::{account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> Result<(), ProgramError> {
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !accounts[1].is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // BUG: no discriminant check before reading vault data
    let vault_data = accounts[1].try_borrow()?;
    let balance = u64::from_le_bytes(vault_data[0..8].try_into().unwrap());
    drop(vault_data);

    Ok(())
}
