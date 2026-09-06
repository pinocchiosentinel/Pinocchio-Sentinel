//! Benchmark: 04-type-cosplay
//! PS-004 should detect: zero-copy cast without data_len()

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

    let vault_data = accounts[1].try_borrow()?;
    // BUG: accessing index 100 without checking data_len()
    let _value = vault_data[100];
    drop(vault_data);

    Ok(())
}
