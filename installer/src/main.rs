//! `proxy-control-installer`: the Proxy Control host installer.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = installer::cli::main();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
