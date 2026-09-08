use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !authority.owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let account = &accounts[1];
    if !account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    if account.data_len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut data = account.try_borrow_mut_data()?;
    if data.len() < 8 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Safe access pattern
    data[0] = 1;
    Ok(())
}
