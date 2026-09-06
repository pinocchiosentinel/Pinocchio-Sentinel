//! Benchmark: 09-closing-accounts
//! PS-009 should detect: lamport reduction without data zeroing

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

    // BUG: reducing lamports without zeroing data
    let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut account_data = accounts[1].try_borrow_mut()?;
    let current = u64::from_le_bytes(account_data[0..8].try_into().unwrap());
    let new_val = current.saturating_sub(lamports);
    account_data[0..8].copy_from_slice(&new_val.to_le_bytes());
    drop(account_data);

    Ok(())
}
