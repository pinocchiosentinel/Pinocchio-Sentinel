//! Benchmark: 02-missing-owner-check
//! PS-002 should detect: vault read without owned_by()

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

    // BUG: accounts[1].owned_by() never called — attacker can pass fake account
    let vault_data = accounts[1].try_borrow()?;
    let _ = &vault_data[0..8];
    drop(vault_data);

    Ok(())
}
