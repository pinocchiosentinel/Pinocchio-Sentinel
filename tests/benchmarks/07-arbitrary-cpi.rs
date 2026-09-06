//! Benchmark: 07-arbitrary-cpi
//! PS-007 should detect: CPI target program ID not checked

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

    // BUG: CPI to accounts[1] without verifying program ID
    let _ = accounts[1].try_borrow_data()?;

    Ok(())
}
