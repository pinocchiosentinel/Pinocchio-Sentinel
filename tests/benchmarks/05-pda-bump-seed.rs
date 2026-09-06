//! Benchmark: 05-pda-bump-seed
//! PS-005 should detect: PDA used without canonical bump

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

    // BUG: using accounts[1] as PDA without verifying canonical bump
    let vault_data = accounts[1].try_borrow()?;
    let _ = &vault_data[0..8];
    drop(vault_data);

    Ok(())
}
