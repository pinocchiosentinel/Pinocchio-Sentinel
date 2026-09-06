use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::{Expr, File, Item, ItemFn, Stmt};

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub file_path: Option<String>,
    pub requires_signer: Vec<usize>,
    pub requires_owner: Vec<usize>,
    pub requires_writable: Vec<usize>,
    pub requires_data_len: Vec<usize>,
    pub performs_cpi: bool,
    pub line_number: u32,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub caller: String,
    pub callee: String,
    pub line_number: u32,
    pub account_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub functions: HashMap<String, FunctionInfo>,
    pub call_sites: Vec<CallSite>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze_file(&mut self, ast: &File, file_path: Option<&str>) {
        for item in &ast.items {
            if let Item::Fn(func) = item {
                let info = self.analyze_function(func, file_path);
                self.functions.insert(info.name.clone(), info);
            }
        }
    }

    fn analyze_function(&self, func: &ItemFn, file_path: Option<&str>) -> FunctionInfo {
        let name = func.sig.ident.to_string();
        let line = line_of_span(func.span());

        let mut requires_signer = Vec::new();
        let mut requires_owner = Vec::new();
        let mut requires_writable = Vec::new();
        let mut requires_data_len = Vec::new();
        let mut performs_cpi = false;

        self.collect_requirements_from_block(
            &func.block,
            &mut requires_signer,
            &mut requires_owner,
            &mut requires_writable,
            &mut requires_data_len,
            &mut performs_cpi,
        );

        FunctionInfo {
            name,
            file_path: file_path.map(|s| s.to_string()),
            requires_signer,
            requires_owner,
            requires_writable,
            requires_data_len,
            performs_cpi,
            line_number: line,
        }
    }

    fn collect_requirements_from_block(
        &self,
        block: &syn::Block,
        requires_signer: &mut Vec<usize>,
        requires_owner: &mut Vec<usize>,
        requires_writable: &mut Vec<usize>,
        requires_data_len: &mut Vec<usize>,
        performs_cpi: &mut bool,
    ) {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Expr(expr, _) => {
                    self.collect_requirements_from_expr(
                        expr,
                        requires_signer,
                        requires_owner,
                        requires_writable,
                        requires_data_len,
                        performs_cpi,
                    );
                }
                Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        self.collect_requirements_from_expr(
                            &init.expr,
                            requires_signer,
                            requires_owner,
                            requires_writable,
                            requires_data_len,
                            performs_cpi,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_requirements_from_expr(
        &self,
        expr: &Expr,
        requires_signer: &mut Vec<usize>,
        requires_owner: &mut Vec<usize>,
        requires_writable: &mut Vec<usize>,
        requires_data_len: &mut Vec<usize>,
        performs_cpi: &mut bool,
    ) {
        match expr {
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                let receiver = &method_call.receiver;

                if let Some(idx) = try_extract_account_index(receiver) {
                    match method_name.as_str() {
                        "is_signer" => requires_signer.push(idx),
                        "owned_by" => requires_owner.push(idx),
                        "is_writable" => requires_writable.push(idx),
                        "data_len" => requires_data_len.push(idx),
                        _ => {}
                    }
                }

                if method_name == "invoke" || method_name == "invoke_signed" {
                    *performs_cpi = true;
                }

                self.collect_requirements_from_expr(
                    receiver,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
                for arg in &method_call.args {
                    self.collect_requirements_from_expr(
                        arg,
                        requires_signer,
                        requires_owner,
                        requires_writable,
                        requires_data_len,
                        performs_cpi,
                    );
                }
            }
            Expr::Call(call) => {
                if let Expr::Path(path) = &*call.func {
                    if let Some(segment) = path.path.segments.last() {
                        let fn_name = segment.ident.to_string();
                        if fn_name == "invoke" || fn_name == "invoke_signed" {
                            *performs_cpi = true;
                        }
                    }
                }
                for arg in &call.args {
                    self.collect_requirements_from_expr(
                        arg,
                        requires_signer,
                        requires_owner,
                        requires_writable,
                        requires_data_len,
                        performs_cpi,
                    );
                }
                self.collect_requirements_from_expr(
                    &call.func,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
            }
            Expr::Block(block_expr) => {
                self.collect_requirements_from_block(
                    &block_expr.block,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
            }
            Expr::If(if_expr) => {
                self.collect_requirements_from_expr(
                    &if_expr.cond,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
                self.collect_requirements_from_block(
                    &if_expr.then_branch,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
                if let Some((_, else_expr)) = &if_expr.else_branch {
                    self.collect_requirements_from_expr(
                        else_expr,
                        requires_signer,
                        requires_owner,
                        requires_writable,
                        requires_data_len,
                        performs_cpi,
                    );
                }
            }
            Expr::Match(match_expr) => {
                self.collect_requirements_from_expr(
                    &match_expr.expr,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
                for arm in &match_expr.arms {
                    self.collect_requirements_from_expr(
                        &arm.body,
                        requires_signer,
                        requires_owner,
                        requires_writable,
                        requires_data_len,
                        performs_cpi,
                    );
                }
            }
            Expr::Paren(paren) => {
                self.collect_requirements_from_expr(
                    &paren.expr,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
            }
            Expr::Binary(binary) => {
                self.collect_requirements_from_expr(
                    &binary.left,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
                self.collect_requirements_from_expr(
                    &binary.right,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
            }
            Expr::Return(ret) => {
                if let Some(expr) = &ret.expr {
                    self.collect_requirements_from_expr(
                        expr,
                        requires_signer,
                        requires_owner,
                        requires_writable,
                        requires_data_len,
                        performs_cpi,
                    );
                }
            }
            Expr::Try(try_expr) => {
                self.collect_requirements_from_expr(
                    &try_expr.expr,
                    requires_signer,
                    requires_owner,
                    requires_writable,
                    requires_data_len,
                    performs_cpi,
                );
            }
            _ => {}
        }
    }

    pub fn find_caller_of(&self, callee_name: &str) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|cs| cs.callee == callee_name)
            .collect()
    }

    pub fn get_function_requirements(&self, fn_name: &str) -> Option<&FunctionInfo> {
        self.functions.get(fn_name)
    }
}

fn try_extract_account_index(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Index(index_expr) => {
            if let Expr::Path(path) = &*index_expr.expr {
                if path
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident == "accounts")
                    .unwrap_or(false)
                {
                    if let Expr::Lit(lit) = &*index_expr.index {
                        if let syn::Lit::Int(int_lit) = &lit.lit {
                            return int_lit.base10_parse::<usize>().ok();
                        }
                    }
                }
            }
            None
        }
        Expr::Reference(ref_expr) => try_extract_account_index(&ref_expr.expr),
        Expr::Paren(paren) => try_extract_account_index(&paren.expr),
        Expr::Try(try_expr) => try_extract_account_index(&try_expr.expr),
        _ => None,
    }
}

fn line_of_span(span: proc_macro2::Span) -> u32 {
    span.start().line as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph() {
        let graph = CallGraph::new();
        assert!(graph.functions.is_empty());
        assert!(graph.call_sites.is_empty());
    }

    #[test]
    fn test_extract_account_index() {
        let code = r#"
            fn test() {
                let idx = accounts[0];
            }
        "#;
        let ast: File = syn::parse_str(code).unwrap();
        if let Item::Fn(func) = &ast.items[0] {
            if let Stmt::Local(local) = &func.block.stmts[0] {
                if let Some(init) = &local.init {
                    assert!(try_extract_account_index(&init.expr).is_some());
                }
            }
        }
    }
}
