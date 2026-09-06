use syn::{File, Item, ItemFn, Expr, ExprMatch, Lit, Pat, Block, Stmt, ExprBlock};
use anyhow::{Result, anyhow};

use super::{InstructionRouter, HandlerInfo, DiscriminatorScheme, DiscriminatorValue, AccountSliceIndex, EntrypointInfo};
use crate::config::SentinelConfig;

const ENTRYPOINT_FN_NAMES: &[&str] = &["process_instruction", "process", "main"];

pub fn recover_router(ast: &File, _entrypoint: &EntrypointInfo, _config: &SentinelConfig) -> Result<InstructionRouter> {
    let entry_fn = find_entrypoint_function(ast)?;
    let match_stmt = find_instruction_match(&entry_fn)?;
    let scheme = infer_discriminator_scheme(&match_stmt);
    let handlers = extract_handlers(&match_stmt, &scheme)?;

    Ok(InstructionRouter {
        discriminator_scheme: scheme,
        handlers,
    })
}

fn find_entrypoint_function(ast: &File) -> Result<&ItemFn> {
    for item in &ast.items {
        if let Item::Fn(func) = item {
            if ENTRYPOINT_FN_NAMES.contains(&func.sig.ident.to_string().as_str()) {
                return Ok(func);
            }
        }
    }
    Err(anyhow!("Could not find entrypoint function"))
}

fn find_instruction_match(func: &ItemFn) -> Result<&ExprMatch> {
    find_match_in_block(&func.block)
}

fn find_match_in_block(block: &Block) -> Result<&ExprMatch> {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Expr(expr, _) => {
                if let Expr::Match(match_expr) = expr {
                    return Ok(match_expr);
                }
                // Recurse into blocks / if-let / match arms
                if let Some(inner) = find_match_in_expr(expr) {
                    return Ok(inner);
                }
            }
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    if let Some(inner) = find_match_in_expr(&init.expr) {
                        return Ok(inner);
                    }
                }
            }
            _ => {}
        }
    }
    Err(anyhow!("Could not find instruction match statement"))
}

fn find_match_in_expr(expr: &Expr) -> Option<&ExprMatch> {
    match expr {
        Expr::Block(ExprBlock { block, .. }) => find_match_in_block(block).ok(),
        Expr::If(if_expr) => {
            find_match_in_block(&if_expr.then_branch).ok()
                .or_else(|| if_expr.else_branch.as_ref().and_then(|(_, else_expr)| find_match_in_expr(else_expr)))
        }
        Expr::Match(match_expr) => Some(match_expr),
        Expr::Closure(closure) => find_match_in_expr(&closure.body),
        _ => None,
    }
}

fn infer_discriminator_scheme(match_expr: &ExprMatch) -> DiscriminatorScheme {
    if let Some(arm) = match_expr.arms.first() {
        if let Pat::Or(or_pat) = &arm.pat {
            if let Some(first_pat) = or_pat.cases.first() {
                return infer_from_pattern(first_pat);
            }
        } else {
            return infer_from_pattern(&arm.pat);
        }
    }
    DiscriminatorScheme::OneByte
}

fn infer_from_pattern(pat: &Pat) -> DiscriminatorScheme {
    match pat {
        Pat::Lit(lit_pat) => match &lit_pat.lit {
            Lit::Int(int_lit) => {
                // Try smallest type first
                if int_lit.base10_parse::<u8>().is_ok() {
                    DiscriminatorScheme::OneByte
                } else if int_lit.base10_parse::<u32>().is_ok() {
                    DiscriminatorScheme::FourByteU32
                } else if int_lit.base10_parse::<u64>().is_ok() {
                    DiscriminatorScheme::EightByte
                } else {
                    DiscriminatorScheme::Inferred("unknown_int_width".to_string())
                }
            }
            Lit::Byte(_) => DiscriminatorScheme::OneByte,
            _ => DiscriminatorScheme::Inferred("unknown_literal".to_string()),
        },
        Pat::Tuple(tuple_pat) => {
            let len = tuple_pat.elems.len();
            // Check if elements are byte/int literals
            if tuple_pat.elems.iter().all(|e| matches!(e, Pat::Lit(_))) {
                match len {
                    1 => DiscriminatorScheme::OneByte,
                    4 => DiscriminatorScheme::FourByteU32,
                    8 => DiscriminatorScheme::EightByte,
                    _ => DiscriminatorScheme::Inferred(format!("tuple_{}", len)),
                }
            } else {
                DiscriminatorScheme::Inferred(format!("tuple_{}", len))
            }
        }
        Pat::Path(path_pat) => {
            // Wildcard or named variant — default to OneByte
            if path_pat.qself.is_none() && path_pat.path.is_ident("_") {
                DiscriminatorScheme::OneByte
            } else {
                DiscriminatorScheme::Inferred("path_pattern".to_string())
            }
        }
        _ => DiscriminatorScheme::Inferred("unknown_pattern".to_string()),
    }
}

fn extract_handlers(match_expr: &ExprMatch, scheme: &DiscriminatorScheme) -> Result<Vec<HandlerInfo>> {
    let mut handlers = Vec::new();

    for arm in &match_expr.arms {
        let disc_value = extract_discriminator_value(&arm.pat, scheme)?;
        let handler_name = extract_handler_name(&arm.body);
        let account_indices = extract_account_indices_from_expr(&arm.body);

        handlers.push(HandlerInfo {
            discriminator_value: disc_value,
            handler_name,
            account_slice_indices: account_indices,
        });
    }

    Ok(handlers)
}

fn extract_discriminator_value(pat: &Pat, scheme: &DiscriminatorScheme) -> Result<DiscriminatorValue> {
    match pat {
        Pat::Lit(lit_pat) => match &lit_pat.lit {
            Lit::Int(int_lit) => match scheme {
                DiscriminatorScheme::OneByte => {
                    let val: u8 = int_lit.base10_parse()?;
                    Ok(DiscriminatorValue::OneByte(val))
                }
                DiscriminatorScheme::FourByteU32 => {
                    let val: u32 = int_lit.base10_parse()?;
                    Ok(DiscriminatorValue::FourByteU32(val))
                }
                DiscriminatorScheme::EightByte => {
                    let val: u64 = int_lit.base10_parse()?;
                    Ok(DiscriminatorValue::EightByte(val.to_le_bytes()))
                }
                _ => Err(anyhow!("Unsupported discriminator scheme for literal")),
            },
            Lit::Byte(byte_lit) => Ok(DiscriminatorValue::OneByte(byte_lit.value())),
            _ => Err(anyhow!("Unsupported literal type in discriminator")),
        },
        Pat::Tuple(tuple_pat) => {
            let mut bytes = [0u8; 8];
            for (i, elem) in tuple_pat.elems.iter().enumerate().take(8) {
                match elem {
                    Pat::Lit(lp) => match &lp.lit {
                        Lit::Byte(bl) => bytes[i] = bl.value(),
                        Lit::Int(il) => bytes[i] = il.base10_parse().unwrap_or(0),
                        _ => {}
                    },
                    _ => {}
                }
            }
            match scheme {
                DiscriminatorScheme::EightByte => Ok(DiscriminatorValue::EightByte(bytes)),
                DiscriminatorScheme::FourByteU32 => {
                    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    Ok(DiscriminatorValue::FourByteU32(val))
                }
                DiscriminatorScheme::OneByte => Ok(DiscriminatorValue::OneByte(bytes[0])),
                _ => Err(anyhow!("Unsupported discriminator scheme for tuple")),
            }
        }
        Pat::Or(or_pat) => {
            // For OR patterns, take the first case
            if let Some(first) = or_pat.cases.first() {
                extract_discriminator_value(first, scheme)
            } else {
                Err(anyhow!("Empty OR pattern"))
            }
        }
        Pat::Wild(_) => Ok(DiscriminatorValue::OneByte(0xFF)), // wildcard / catch-all
        _ => Err(anyhow!("Unsupported pattern type in discriminator")),
    }
}

fn extract_handler_name(expr: &Expr) -> String {
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                if let Some(segment) = path.path.segments.last() {
                    return segment.ident.to_string();
                }
            }
        }
        Expr::Block(block) => {
            for stmt in &block.block.stmts {
                if let Stmt::Expr(expr, _) = stmt {
                    let name = extract_handler_name(expr);
                    if name != "unknown_handler" {
                        return name;
                    }
                }
            }
        }
        Expr::Macro(mac) => {
            // macro invocation — try to extract name from tokens
            let tokens = mac.mac.tokens.to_string();
            // Heuristic: first identifier in macro
            if let Some(pos) = tokens.find('(') {
                let before = tokens[..pos].trim();
                if !before.is_empty() {
                    return before.to_string();
                }
            }
        }
        _ => {}
    }
    "unknown_handler".to_string()
}

fn extract_account_indices_from_expr(expr: &Expr) -> Vec<AccountSliceIndex> {
    let mut indices = Vec::new();
    collect_account_indices(expr, &mut indices);
    // Deduplicate by index
    indices.sort_by_key(|a| a.index);
    indices.dedup_by_key(|a| a.index);
    indices
}

fn collect_account_indices(expr: &Expr, indices: &mut Vec<AccountSliceIndex>) {
    match expr {
        Expr::Call(call) => {
            // Check each argument for accounts[...] or accounts.get(...)
            for arg in &call.args {
                if let Some(idx) = try_extract_account_index(arg) {
                    indices.push(idx);
                }
                collect_account_indices(arg, indices);
            }
            // Also check the callee (e.g. method call receiver)
            collect_account_indices(&call.func, indices);
        }
        Expr::Index(index_expr) => {
            // accounts[n]
            if let Some(idx) = try_extract_account_index(&Expr::Index(index_expr.clone())) {
                indices.push(idx);
            }
        }
        Expr::MethodCall(method_call) => {
            // accounts.get(n) or accounts[n].method()
            if let Some(idx) = try_extract_account_index_from_receiver(&method_call.receiver) {
                indices.push(idx);
            }
            for arg in &method_call.args {
                collect_account_indices(arg, indices);
            }
            collect_account_indices(&method_call.receiver, indices);
        }
        Expr::Block(ExprBlock { block, .. }) => {
            collect_account_indices_in_block(block, indices);
        }
        Expr::If(if_expr) => {
            collect_account_indices(&if_expr.cond, indices);
            collect_account_indices_in_block(&if_expr.then_branch, indices);
            if let Some((_, else_expr)) = &if_expr.else_branch {
                collect_account_indices(else_expr, indices);
            }
        }
        Expr::Match(match_expr) => {
            collect_account_indices(&match_expr.expr, indices);
            for arm in &match_expr.arms {
                collect_account_indices(&arm.body, indices);
            }
        }
        Expr::Paren(paren) => {
            collect_account_indices(&paren.expr, indices);
        }
        Expr::Binary(binary) => {
            collect_account_indices(&binary.left, indices);
            collect_account_indices(&binary.right, indices);
        }
        Expr::Unary(unary) => {
            collect_account_indices(&unary.expr, indices);
        }
        Expr::Return(ret) => {
            if let Some(expr) = &ret.expr {
                collect_account_indices(expr, indices);
            }
        }
        _ => {}
    }
}

fn collect_account_indices_in_block(block: &Block, indices: &mut Vec<AccountSliceIndex>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Expr(expr, _) => {
                collect_account_indices(expr, indices);
            }
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    collect_account_indices(&init.expr, indices);
                }
            }
            _ => {}
        }
    }
}

fn try_extract_account_index(expr: &Expr) -> Option<AccountSliceIndex> {
    if let Expr::Index(index_expr) = expr {
        if let Expr::Path(path) = &*index_expr.expr {
            if path.path.segments.last().map(|s| s.ident == "accounts").unwrap_or(false) {
                if let Expr::Lit(lit) = &*index_expr.index {
                    if let Lit::Int(int_lit) = &lit.lit {
                        if let Ok(idx) = int_lit.base10_parse::<usize>() {
                            return Some(AccountSliceIndex {
                                index: idx,
                                variable_name: format!("accounts[{}]", idx),
                            });
                        }
                    }
                }
            }
        }
    }
    None
}

fn try_extract_account_index_from_receiver(receiver: &Expr) -> Option<AccountSliceIndex> {
    // Check if receiver is accounts[n]
    if let Some(idx) = try_extract_account_index(receiver) {
        return Some(idx);
    }

    // Check for accounts.get(n) — method call
    if let Expr::MethodCall(method_call) = receiver {
        if method_call.method == "get" && method_call.args.len() == 1 {
            if let Expr::Path(path) = &*method_call.receiver {
                if path.path.segments.last().map(|s| s.ident == "accounts").unwrap_or(false) {
                    if let Expr::Lit(lit) = &method_call.args[0] {
                        if let Lit::Int(int_lit) = &lit.lit {
                            if let Ok(idx) = int_lit.base10_parse::<usize>() {
                                return Some(AccountSliceIndex {
                                    index: idx,
                                    variable_name: format!("accounts[{}]", idx),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
