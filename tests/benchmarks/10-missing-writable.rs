//! Benchmark: 10-missing-writable
//! PS-010 should detect: account mutated without is_writable()

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

    // BUG: mutating accounts[1] without checking is_writable()
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut vault_data = accounts[1].try_borrow_mut()?;
    vault_data[0..8].copy_from_slice(&amount.to_le_bytes());
    drop(vault_data);

    Ok(())
}
