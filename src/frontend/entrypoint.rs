use syn::{File, Item, Macro};
use syn::spanned::Spanned;
use super::{EntrypointInfo, EntrypointMacro};

const ENTRYPOINT_MACROS: &[&str] = &[
    "entrypoint",
    "lazy_program_entrypoint",
    "no_allocator",
];

pub fn find_entrypoint(ast: &File) -> Option<EntrypointInfo> {
    for item in &ast.items {
        match item {
            Item::Macro(mac) => {
                if let Some(info) = check_macro_invocation(&mac.mac) {
                    return Some(info);
                }
            }
            _ => {}
        }
    }
    None
}

fn check_macro_invocation(mac: &Macro) -> Option<EntrypointInfo> {
    let macro_name = mac.path.segments.last()?.ident.to_string();
    
    let macro_type = match macro_name.as_str() {
        "entrypoint" => EntrypointMacro::Entrypoint,
        "lazy_program_entrypoint" => EntrypointMacro::LazyProgramEntrypoint,
        "no_allocator" => EntrypointMacro::NoAllocator,
        _ => return None,
    };
    
    Some(EntrypointInfo {
        macro_type,
        span: mac.span(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn test_find_entrypoint() {
        let code = quote! {
            solana_program::entrypoint!(process_instruction);
        };
        let ast = syn::parse_file(&code.to_string()).unwrap();
        let result = find_entrypoint(&ast);
        assert!(result.is_some());
        assert_eq!(result.unwrap().macro_type, EntrypointMacro::Entrypoint);
    }

    #[test]
    fn test_find_lazy_entrypoint() {
        let code = quote! {
            pinocchio::lazy_program_entrypoint!(process_instruction);
        };
        let ast = syn::parse_file(&code.to_string()).unwrap();
        let result = find_entrypoint(&ast);
        assert!(result.is_some());
        assert_eq!(result.unwrap().macro_type, EntrypointMacro::LazyProgramEntrypoint);
    }

    #[test]
    fn test_no_entrypoint() {
        let code = quote! {
            fn main() {}
        };
        let ast = syn::parse_file(&code.to_string()).unwrap();
        let result = find_entrypoint(&ast);
        assert!(result.is_none());
    }
}
