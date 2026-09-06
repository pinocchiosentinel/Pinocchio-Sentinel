//! Benchmark: 10-duplicate-mutable-accounts
//! PS-006 should detect: two account indices may alias, both mutated

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

    // BUG: accounts[1] and accounts[2] could be the same account (aliasing)
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());

    let src_data = accounts[1].try_borrow()?;
    let balance = u64::from_le_bytes(src_data[0..8].try_into().unwrap());
    drop(src_data);

    let mut dest_data = accounts[2].try_borrow_mut()?;
    dest_data[0..8].copy_from_slice(&(balance + amount).to_le_bytes());
    drop(dest_data);

    Ok(())
}
