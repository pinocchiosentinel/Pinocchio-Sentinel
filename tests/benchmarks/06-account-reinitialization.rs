//! Benchmark: 06-account-reinitialization
//! PS-008 should detect: init account without discriminant check

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

    // BUG: writing to accounts[1] without checking if already initialized
    let mut state_data = accounts[1].try_borrow_mut()?;
    state_data[0..8].copy_from_slice(&data[0..8]);
    drop(state_data);

    Ok(())
}
