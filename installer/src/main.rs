//! `proxy-control-installer`: the Proxy Control host installer.

use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("three-xui-bootstrap") {
        use std::io::Read;
        let mut bytes = Vec::new();
        let result = std::io::stdin()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| ())
            .and(if bytes.len() > 65536 { Err(()) } else { Ok(()) })
            .and_then(|_| serde_json::from_slice(&bytes).map_err(|_| ()))
            .and_then(|payload| installer::adapters::three_xui::bootstrap_dialogue(&payload).map_err(|_| ()));
        if result.is_err() {
            eprintln!("3x-ui bootstrap failed");
        }
        return ExitCode::from(if result.is_ok() { 0 } else { 1 });
    }
    let code = installer::cli::main();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
