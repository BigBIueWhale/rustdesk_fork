//! Extract creation-mode expressions for a compiler-only Darwin ABI fixture.

use quote::ToTokens;
use std::{env, error::Error, fs, path::PathBuf};
use syn::{visit::Visit, Expr, ExprCall, ItemFn};

struct Case {
    name: &'static str,
    file: &'static str,
    function: &'static str,
    call: &'static str,
    arguments: usize,
    variadic: bool,
}

const CASES: &[Case] = &[
    Case { name: "config", file: "libs/hbb_common/src/config.rs", function: "store_config_bytes_transaction_unix", call: "openat", arguments: 4, variadic: true },
    Case { name: "transfer", file: "libs/hbb_common/src/fs.rs", function: "open_regular_child_no_follow", call: "openat", arguments: 4, variadic: true },
    Case { name: "pid", file: "src/ipc/fs.rs", function: "write_pid_file", call: "open", arguments: 3, variadic: true },
    Case { name: "paste", file: "libs/clipboard/src/platform/unix/macos/paste_task.rs", function: "open_relative_file_exclusive_no_follow", call: "openat", arguments: 4, variadic: true },
    Case { name: "placeholder", file: "libs/clipboard/src/platform/unix/macos/pasteboard_context.rs", function: "create_placeholder_file", call: "openat", arguments: 4, variadic: true },
    Case { name: "config_fixed", file: "libs/hbb_common/src/config.rs", function: "store_config_bytes_transaction_unix", call: "fchmod", arguments: 2, variadic: false },
    Case { name: "paste_fixed", file: "libs/clipboard/src/platform/unix/macos/paste_task.rs", function: "mkdir_child_if_missing", call: "mkdirat", arguments: 3, variadic: false },
    Case { name: "placeholder_fixed", file: "libs/clipboard/src/platform/unix/macos/pasteboard_context.rs", function: "open_private_placeholder_dir", call: "fchmod", arguments: 2, variadic: false },
];

struct Functions<'a> {
    name: &'static str,
    found: Vec<&'a ItemFn>,
}

impl<'a> Visit<'a> for Functions<'a> {
    fn visit_item_fn(&mut self, item: &'a ItemFn) {
        if item.sig.ident == self.name {
            self.found.push(item);
        }
        syn::visit::visit_item_fn(self, item);
    }
}

struct Calls<'a> {
    case: &'a Case,
    modes: Vec<String>,
}

impl<'a, 'ast> Visit<'ast> for Calls<'a> {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = call.func.as_ref() {
            let names: Vec<_> = path.path.segments.iter().map(|p| p.ident.to_string()).collect();
            let owner = names.len() >= 2
                && names[names.len() - 2] == "libc"
                && matches!(names.len(), 2 | 3)
                && (names.len() == 2 || matches!(names[0].as_str(), "crate" | "hbb_common"));
            if path.qself.is_none() && owner && names.last().map(String::as_str) == Some(self.case.call)
                && call.args.len() == self.case.arguments
            {
                if let Some(mode) = call.args.last() {
                    self.modes.push(mode.to_token_stream().to_string());
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=MACOS_FILE_MODE_NEGATIVE");
    let negative = match env::var("MACOS_FILE_MODE_NEGATIVE") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    if negative.as_ref().is_some_and(|name| !CASES.iter().any(|case| case.name == name)) {
        return Err("unknown file-mode negative control".into());
    }
    let mut generated = String::from(
        "#[allow(unused_imports)] pub extern crate libc;\nmod hbb_common { pub use ::libc; }\n",
    );
    for case in CASES {
        let input = PathBuf::from("/work").join(case.file);
        println!("cargo:rerun-if-changed={}", input.display());
        let source = syn::parse_file(&fs::read_to_string(&input)?)?;
        let mut functions = Functions { name: case.function, found: Vec::new() };
        functions.visit_file(&source);
        if functions.found.len() != 1 {
            return Err(format!("ambiguous function for {}", case.name).into());
        }
        let mut calls = Calls { case, modes: Vec::new() };
        calls.visit_block(&functions.found[0].block);
        if calls.modes.len() != 1 {
            return Err(format!("ambiguous mode call for {}", case.name).into());
        }
        let mode = if negative.as_deref() == Some(case.name) {
            if case.variadic { "mode" } else { "0o600 as libc::c_uint" }
        } else {
            &calls.modes[0]
        };
        let arguments = match case.call {
            "openat" => format!("0, std::ptr::null(), 0, {mode}"),
            "open" => format!("std::ptr::null(), 0, {mode}"),
            "fchmod" => format!("0, {mode}"),
            "mkdirat" => format!("0, std::ptr::null(), {mode}"),
            _ => return Err("unsupported mode-call prototype".into()),
        };
        generated.push_str(&format!(
            "#[allow(dead_code, unused_variables)]\nunsafe fn mode_case_{}(mode: libc::mode_t) {{\n    libc::{}({});\n}}\n",
            case.name, case.call, arguments,
        ));
    }
    fs::write(PathBuf::from(env::var("OUT_DIR")?).join("modes.rs"), generated)?;
    Ok(())
}
