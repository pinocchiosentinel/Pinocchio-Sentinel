pub mod entrypoint;
pub mod router;
pub mod discriminator;

use syn::File;
use std::path::{Path, PathBuf};

use crate::config::SentinelConfig;

#[derive(Debug, Clone)]
pub struct ParsedProgram {
    pub ast: File,
    pub entrypoint: Option<EntrypointInfo>,
    pub router: Option<InstructionRouter>,
    pub source_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct EntrypointInfo {
    pub macro_type: EntrypointMacro,
    pub span: proc_macro2::Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EntrypointMacro {
    Entrypoint,
    LazyProgramEntrypoint,
    NoAllocator,
}

#[derive(Debug, Clone)]
pub struct InstructionRouter {
    pub discriminator_scheme: DiscriminatorScheme,
    pub handlers: Vec<HandlerInfo>,
}

#[derive(Debug, Clone)]
pub struct HandlerInfo {
    pub discriminator_value: DiscriminatorValue,
    pub handler_name: String,
    pub account_slice_indices: Vec<AccountSliceIndex>,
}

#[derive(Debug, Clone)]
pub enum DiscriminatorScheme {
    /// 1-byte tag (e.g., token programs)
    OneByte,
    /// 4-byte u32 (e.g., system programs)
    FourByteU32,
    /// 8-byte anchor-style (for reference)
    EightByte,
    /// Inferred from code
    Inferred(String),
}

#[derive(Debug, Clone)]
pub enum DiscriminatorValue {
    OneByte(u8),
    FourByteU32(u32),
    EightByte([u8; 8]),
}

#[derive(Debug, Clone)]
pub struct AccountSliceIndex {
    pub index: usize,
    pub variable_name: String,
}

pub fn parse_program(path: &Path, config: &SentinelConfig) -> anyhow::Result<ParsedProgram> {
    let source = std::fs::read_to_string(path)?;
    let ast = syn::parse_file(&source)?;
    
    let entrypoint = entrypoint::find_entrypoint(&ast);
    let router = if let Some(ref ep) = entrypoint {
        Some(router::recover_router(&ast, ep, config)?)
    } else {
        None
    };
    
    Ok(ParsedProgram {
        ast,
        entrypoint,
        router,
        source_path: path.to_path_buf(),
    })
}
