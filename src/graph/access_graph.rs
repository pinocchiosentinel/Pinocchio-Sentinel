use crate::frontend::HandlerInfo;
use syn::{File, Item, ItemFn, Expr, Stmt, ExprMethodCall, ExprBlock, Pat, Lit, ExprStruct};
use syn::spanned::Spanned;

#[derive(Debug, Clone, PartialEq)]
pub enum AccessType {
    Read,
    Write,
    Both,
}

#[derive(Debug, Clone)]
pub struct AccountAccess {
    pub index: usize,
    pub variable_name: String,
    pub access_type: AccessType,
    pub checks: Vec<CheckInfo>,
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CheckInfo {
    pub check_type: CheckType,
    pub line_number: u32,
    pub is_before_use: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckType {
    IsSigner,
    OwnedBy,
    IsWritable,
    DataLen,
    Discriminant,
    PdaBump,
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct AccountAccessGraph {
    pub handler_name: String,
    pub accounts: Vec<AccountAccess>,
    pub access_order: Vec<usize>,
}

impl AccountAccessGraph {
    pub fn new(handler_name: &str) -> Self {
        Self {
            handler_name: handler_name.to_string(),
            accounts: Vec::new(),
            access_order: Vec::new(),
        }
    }

    pub fn add_account(&mut self, access: AccountAccess) {
        self.access_order.push(access.index);
        self.accounts.push(access);
    }

    pub fn get_account(&self, index: usize) -> Option<&AccountAccess> {
        self.accounts.iter().find(|a| a.index == index)
    }

    pub fn get_account_mut(&mut self, index: usize) -> Option<&mut AccountAccess> {
        self.accounts.iter_mut().find(|a| a.index == index)
    }

    pub fn get_checks_before_use(&self, index: usize) -> Vec<&CheckInfo> {
        if let Some(account) = self.get_account(index) {
            account.checks.iter().filter(|c| c.is_before_use).collect()
        } else {
            Vec::new()
        }
    }

    pub fn has_check_before_use(&self, index: usize, check_type: &CheckType) -> bool {
        self.get_checks_before_use(index)
            .iter()
            .any(|c| &c.check_type == check_type)
    }
}

pub fn build_access_graph(handler: &HandlerInfo, ast: &File) -> AccountAccessGraph {
    let mut graph = AccountAccessGraph::new(&handler.handler_name);

    // Find the handler function in the AST
    let handler_fn = find_function_by_name(ast, &handler.handler_name);

    // Collect account indices from the handler info
    let account_indices: Vec<usize> = handler.account_slice_indices.iter().map(|a| a.index).collect();

    // Pre-populate the graph with known account indices
    for idx in &account_indices {
        if graph.get_account(*idx).is_none() {
            graph.add_account(AccountAccess {
                index: *idx,
                variable_name: format!("accounts[{}]", idx),
                access_type: AccessType::Read, // default
                checks: Vec::new(),
                line_number: None,
            });
        }
    }

    // If we found the handler function, traverse its body
    if let Some(handler_fn) = handler_fn {
        let mut collector = CheckCollector {
            account_indices: account_indices.clone(),
            checks: Vec::new(),
            line_number_start: line_of_span(handler_fn.span()),
        };

        // Collect all checks from the function body
        collect_checks_from_block(&handler_fn.block, &mut collector);

        // Assign checks to accounts in the graph
        for check in &collector.checks {
            if let Some(ref account_idx) = check.account_index {
                let idx = *account_idx;
                // Ensure the account exists in the graph
                if graph.get_account(idx).is_none() {
                    graph.add_account(AccountAccess {
                        index: idx,
                        variable_name: format!("accounts[{}]", idx),
                        access_type: AccessType::Read,
                        checks: Vec::new(),
                        line_number: None,
                    });
                }
                if let Some(account) = graph.get_account_mut(idx) {
                    account.checks.push(CheckInfo {
                        check_type: check.check_type.clone(),
                        line_number: check.line_number,
                        is_before_use: check.is_before_use,
                    });
                    // Update access type based on check
                    match &check.check_type {
                        CheckType::IsWritable => {
                            if account.access_type == AccessType::Read {
                                account.access_type = AccessType::Write;
                            } else {
                                account.access_type = AccessType::Both;
                            }
                        }
                        _ => {
                            // Read checks don't change access type beyond Read
                        }
                    }
                }
            }
        }

        // Set line numbers from first use
        for idx in &account_indices {
            if let Some(account) = graph.get_account_mut(*idx) {
                if account.line_number.is_none() {
                    account.line_number = Some(collector.line_number_start);
                }
            }
        }
    }

    graph
}

fn find_function_by_name<'a>(ast: &'a File, name: &str) -> Option<&'a ItemFn> {
    for item in &ast.items {
        if let Item::Fn(func) = item {
            if func.sig.ident == name {
                return Some(func);
            }
        }
    }
    None
}

struct CollectedCheck {
    check_type: CheckType,
    line_number: u32,
    account_index: Option<usize>,
    is_before_use: bool,
}

struct CheckCollector {
    account_indices: Vec<usize>,
    checks: Vec<CollectedCheck>,
    line_number_start: u32,
}

fn collect_checks_from_block(block: &syn::Block, collector: &mut CheckCollector) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Expr(expr, _) => {
                collect_checks_from_expr(expr, collector);
            }
            Stmt::Local(local) => {
                // let accounts = ...; — may contain account slice
                if let Some(init) = &local.init {
                    collect_checks_from_expr(&init.expr, collector);
                }
            }
            _ => {}
        }
    }
}

fn collect_checks_from_expr(expr: &Expr, collector: &mut CheckCollector) {
    match expr {
        Expr::MethodCall(method_call) => {
            let line = line_of_span(method_call.span());
            analyze_method_call(method_call, line, collector);
            // Also recurse into receiver and args
            collect_checks_from_expr(&method_call.receiver, collector);
            for arg in &method_call.args {
                collect_checks_from_expr(arg, collector);
            }
        }
        Expr::Call(call) => {
            for arg in &call.args {
                collect_checks_from_expr(arg, collector);
            }
            collect_checks_from_expr(&call.func, collector);
        }
        Expr::Block(ExprBlock { block, .. }) => {
            collect_checks_from_block(block, collector);
        }
        Expr::If(if_expr) => {
            collect_checks_from_expr(&if_expr.cond, collector);
            collect_checks_from_block(&if_expr.then_branch, collector);
            if let Some((_, else_expr)) = &if_expr.else_branch {
                collect_checks_from_expr(else_expr, collector);
            }
        }
        Expr::Match(match_expr) => {
            collect_checks_from_expr(&match_expr.expr, collector);
            for arm in &match_expr.arms {
                // Check for discriminant check pattern
                analyze_match_arm_pattern(&arm.pat, collector);
                collect_checks_from_expr(&arm.body, collector);
            }
        }
        Expr::Paren(paren) => {
            collect_checks_from_expr(&paren.expr, collector);
        }
        Expr::Binary(binary) => {
            collect_checks_from_expr(&binary.left, collector);
            collect_checks_from_expr(&binary.right, collector);
        }
        Expr::Unary(unary) => {
            collect_checks_from_expr(&unary.expr, collector);
        }
        Expr::Return(ret) => {
            if let Some(expr) = &ret.expr {
                collect_checks_from_expr(expr, collector);
            }
        }
        Expr::Index(index_expr) => {
            collect_checks_from_expr(&index_expr.expr, collector);
            collect_checks_from_expr(&index_expr.index, collector);
        }
        Expr::Path(_) => {
            // Potential account variable reference — no action needed
        }
        Expr::Lit(_) => {}
        Expr::Struct(ExprStruct { fields, .. }) => {
            for field in fields {
                collect_checks_from_expr(&field.expr, collector);
            }
        }
        Expr::Try(try_expr) => {
            collect_checks_from_expr(&try_expr.expr, collector);
        }
        Expr::Field(field_expr) => {
            collect_checks_from_expr(&field_expr.base, collector);
        }
        Expr::Array(array_expr) => {
            for elem in &array_expr.elems {
                collect_checks_from_expr(elem, collector);
            }
        }
        Expr::Tuple(tuple_expr) => {
            for elem in &tuple_expr.elems {
                collect_checks_from_expr(elem, collector);
            }
        }
        Expr::Repeat(repeat_expr) => {
            collect_checks_from_expr(&repeat_expr.expr, collector);
            collect_checks_from_expr(&repeat_expr.len, collector);
        }
        Expr::Reference(ref_expr) => {
            collect_checks_from_expr(&ref_expr.expr, collector);
        }
        Expr::Break(break_expr) => {
            if let Some(expr) = &break_expr.expr {
                collect_checks_from_expr(expr, collector);
            }
        }
        Expr::Continue(_) => {}
        Expr::Macro(_) => {}
        Expr::Verbatim(_) => {}
        _ => {}
    }
}

fn analyze_method_call(method_call: &ExprMethodCall, line: u32, collector: &mut CheckCollector) {
    let method_name = method_call.method.to_string();
    let receiver = &method_call.receiver;

    // Determine which account index this call applies to
    let account_index = resolve_account_index(receiver, collector);

    match method_name.as_str() {
        "is_signer" => {
            collector.checks.push(CollectedCheck {
                check_type: CheckType::IsSigner,
                line_number: line,
                account_index,
                is_before_use: true, // assume before use; rules will validate
            });
        }
        "owned_by" => {
            collector.checks.push(CollectedCheck {
                check_type: CheckType::OwnedBy,
                line_number: line,
                account_index,
                is_before_use: true,
            });
        }
        "is_writable" => {
            collector.checks.push(CollectedCheck {
                check_type: CheckType::IsWritable,
                line_number: line,
                account_index,
                is_before_use: true,
            });
        }
        "data_len" => {
            collector.checks.push(CollectedCheck {
                check_type: CheckType::DataLen,
                line_number: line,
                account_index,
                is_before_use: true,
            });
        }
        _ => {
            // Any other method call — could be a custom check or actual use
            // For now, only record it as a check if the name contains "check" or "is"
            if method_name.starts_with("is_") || method_name.contains("check") {
                collector.checks.push(CollectedCheck {
                    check_type: CheckType::Custom(method_name),
                    line_number: line,
                    account_index,
                    is_before_use: true,
                });
            }
        }
    }
}

fn analyze_match_arm_pattern(pat: &Pat, collector: &mut CheckCollector) {
    // Detect discriminant check patterns in match arms
    // e.g., match instruction_data[0] { 0 => ..., 1 => ... }
    // The match expression (before the arm) is already handled in the outer call
    match pat {
        Pat::Lit(lit_pat) => {
            if matches!(&lit_pat.lit, Lit::Int(_) | Lit::Byte(_)) {
                // This is a discriminator value pattern
                collector.checks.push(CollectedCheck {
                    check_type: CheckType::Discriminant,
                    line_number: line_of_span(lit_pat.span()),
                    account_index: None, // discriminant is on instruction data, not an account
                    is_before_use: true,
                });
            }
        }
        Pat::Or(or_pat) => {
            for case in &or_pat.cases {
                analyze_match_arm_pattern(case, collector);
            }
        }
        Pat::Tuple(tuple_pat) => {
            for elem in &tuple_pat.elems {
                analyze_match_arm_pattern(elem, collector);
            }
        }
        Pat::Wild(_) => {
            // Wildcard arm — no discriminant check needed
        }
        _ => {}
    }
}

fn resolve_account_index(expr: &Expr, collector: &mut CheckCollector) -> Option<usize> {
    match expr {
        Expr::Index(index_expr) => {
            // accounts[n]
            if let Expr::Path(path) = &*index_expr.expr {
                if path.path.segments.last().map(|s| s.ident == "accounts").unwrap_or(false) {
                    if let Expr::Lit(lit) = &*index_expr.index {
                        if let Lit::Int(int_lit) = &lit.lit {
                            return int_lit.base10_parse::<usize>().ok();
                        }
                    }
                }
            }
            // Could be accounts_var[n] — try to resolve variable
            resolve_account_index(&index_expr.expr, collector)
        }
        Expr::MethodCall(method_call) => {
            // accounts.get(n)
            if method_call.method == "get" && method_call.args.len() == 1 {
                if let Expr::Path(path) = &*method_call.receiver {
                    if path.path.segments.last().map(|s| s.ident == "accounts").unwrap_or(false) {
                        if let Expr::Lit(lit) = &method_call.args[0] {
                            if let Lit::Int(int_lit) = &lit.lit {
                                return int_lit.base10_parse::<usize>().ok();
                            }
                        }
                    }
                }
            }
            resolve_account_index(&method_call.receiver, collector)
        }
        Expr::Path(path) => {
            // Variable name — check if it maps to an account
            let var_name = path.path.segments.last()?.ident.to_string();
            // Heuristic: if variable is named like "account_0" or "acc_0"
            if var_name.starts_with("account_") || var_name.starts_with("acc_") {
                let suffix = var_name.trim_start_matches("account_").trim_start_matches("acc_");
                suffix.parse::<usize>().ok()
            } else {
                None
            }
        }
        Expr::Paren(paren) => resolve_account_index(&paren.expr, collector),
        _ => None,
    }
}

fn line_of_span(span: proc_macro2::Span) -> u32 {
    // syn spans give start location; extract line number
    let start = span.start();
    start.line as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph() {
        let graph = AccountAccessGraph::new("test_handler");
        assert_eq!(graph.handler_name, "test_handler");
        assert!(graph.accounts.is_empty());
    }

    #[test]
    fn test_add_account() {
        let mut graph = AccountAccessGraph::new("test_handler");
        let access = AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: None,
        };
        graph.add_account(access);
        assert_eq!(graph.accounts.len(), 1);
        assert_eq!(graph.access_order, vec![0]);
    }
}
