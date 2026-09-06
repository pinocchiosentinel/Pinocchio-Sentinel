//! Benchmark: 12-sysvar-account-validation
//! PS-014 should detect: sysvar account without pubkey comparison

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

    // BUG: using accounts[1] as clock sysvar without checking if it's the real sysvar
    let clock_data = accounts[1].try_borrow()?;
    let slot = u64::from_le_bytes(clock_data[0..8].try_into().unwrap());
    drop(clock_data);

    let mut record_data = accounts[2].try_borrow_mut()?;
    record_data[0..8].copy_from_slice(&slot.to_le_bytes());
    drop(record_data);

    Ok(())
}
