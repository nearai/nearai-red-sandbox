//! rts: run an opencode session whose tools execute in a throwaway mvm microVM.
//!
//!   rts launch --config <path>   start one session (operator entry point)
//!   rts tool <name>              one sandboxed tool call, spawned by the plugin shim

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use rts::{bridge, config, session};

const USAGE: &str = "usage: rts launch --config <path>\n       rts tool <shell|read|write|edit|glob|grep>   (request JSON on stdin)";

fn code(c: i32) -> ExitCode {
    ExitCode::from(u8::try_from(c).unwrap_or(1))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["launch", "--config", file] => {
            let cfg = match config::load_config(Path::new(file), &config::Defaults::from_env()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[rts] {e}");
                    return ExitCode::from(1);
                }
            };
            match session::Deps::real() {
                Ok(deps) => code(session::run_session(&cfg, deps)),
                Err(e) => {
                    eprintln!("[rts] {e}");
                    ExitCode::from(1)
                }
            }
        }
        ["tool", name] => {
            let out = bridge::run(name);
            let _ = std::io::stdout().write_all(out.stdout.as_bytes());
            if !out.stderr.is_empty() {
                eprintln!("{}", out.stderr.trim_end());
            }
            code(out.code)
        }
        ["--help" | "-h" | "help"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
