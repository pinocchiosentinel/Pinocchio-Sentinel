use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data[0];
    
    match instruction {
        // Vulnerable: No signer check on authority account
        0 => {
            let authority = &accounts[0];
            let _data = authority.try_borrow_data()?;
            // Uses authority without checking is_signer
            Ok(())
        }
        
        // Vulnerable: No owner check before reading account data
        1 => {
            let account = &accounts[0];
            let data = account.try_borrow_data()?;
            // Reads data without checking owned_by
            Ok(())
        }
        
        // Vulnerable: No discriminant check before cast
        2 => {
            let account = &accounts[0];
            let data = account.try_borrow_data()?;
            // Casts without checking discriminant
            let _value = data[0];
            Ok(())
        }
        
        // Vulnerable: Zero-copy cast without data_len check
        3 => {
            let account = &accounts[0];
            let data = account.try_borrow_data()?;
            // Accesses data without bounds check
            let _value = data[100]; // Could be out of bounds
            Ok(())
        }
        
        // Safe: Has signer check
        4 => {
            let authority = &accounts[0];
            if !authority.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let _data = authority.try_borrow_data()?;
            Ok(())
        }
        
        // Safe: Has owner check
        5 => {
            let account = &accounts[0];
            if !account.owned_by(&crate::ID) {
                return Err(ProgramError::IncorrectProgramId);
            }
            let _data = account.try_borrow_data()?;
            Ok(())
        }
        
        // Vulnerable: lazy_program_entrypoint without account count gate
        6 => {
            // Direct access without checking accounts.len()
            let _account = &accounts[0];
            Ok(())
        }
        
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
