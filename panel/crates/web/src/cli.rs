//! `panel cli …` — the administration commands of `python -m panel.cli` (`panel/cli.py`), and
//! `panel stage-secret verify|stage` (`panel/stage_secret.py`).
//!
//! This is the skeleton of WP4: the commands the harness and the installer need first
//! (`create-admin --password-stdin`, `api-key-create`, `master-key-init`) with Python's stdout,
//! messages and exit codes (0; 2 for a usage error, as argparse; 1 for a failure Python let escape
//! as a traceback). The other commands answer exit 2 until WP14 ports them.

use std::io::Write as _;
use std::path::PathBuf;

use panel_core::db::Database;
use panel_core::settings::py_path;
use panel_secrets::api_keys::{ApiKeyService, SCOPES};
use panel_secrets::audit::Actor;
use panel_secrets::keyring::Keyring;
use panel_secrets::store::Store;
use serde_json::json;

/// The commands of `cli.py`, for the usage line.
const COMMANDS: &str = "create-admin,fleet-register-node,fleet-ca-init,fleet-sign-csr,fleet-bind-cert,fleet-revoke-cert,db-migrate,db-status,master-key-init,master-key-rotate,master-key-verify,operations-resume,node-list,node-disable,node-enable,api-key-create,api-key-revoke";

/// How a command ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Ok,
    /// argparse's `parser.error`: usage + message on stderr, exit 2.
    Usage {
        prog: String,
        message: String,
    },
    /// An exception Python did not catch: exit 1.
    Failed(String),
}

impl Exit {
    pub fn code(&self) -> i32 {
        match self {
            Exit::Ok => 0,
            Exit::Usage { .. } => 2,
            Exit::Failed(_) => 1,
        }
    }
}

fn usage(prog: &str, message: impl Into<String>) -> Exit {
    Exit::Usage { prog: prog.to_string(), message: message.into() }
}

/// Runs `panel cli <args>`; writes the command's stdout to `out`.
pub fn run(args: &[String], stdin: &mut dyn std::io::BufRead, out: &mut dyn std::io::Write) -> Exit {
    let prog = "cli.py";
    let mut index = 0;
    let mut database: Option<PathBuf> = None;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--database" {
            let Some(value) = args.get(index + 1) else {
                return usage(prog, "argument --database: expected one argument");
            };
            database = Some(py_path(value));
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--database=") {
            database = Some(py_path(value));
            index += 1;
        } else {
            break;
        }
    }
    let Some(command) = args.get(index) else {
        return usage(prog, "the following arguments are required: command");
    };
    let database = database.unwrap_or_else(|| {
        py_path(&std::env::var("PANEL_DATABASE").unwrap_or_else(|_| "/data/panel.sqlite3".to_string()))
    });
    let options = Options::parse(&args[index + 1..]);
    let sub = format!("{prog} {command}");
    match command.as_str() {
        "create-admin" => create_admin(&sub, &database, options, stdin, out),
        "api-key-create" => api_key_create(&sub, &database, options, out),
        "master-key-init" => master_key_init(&sub, options, out),
        other if COMMANDS.split(',').any(|name| name == other) => {
            usage(&sub, format!("{other} is not available in this build yet"))
        }
        other => usage(
            prog,
            format!("argument command: invalid choice: {} (choose from {})", panel_core::pytext::repr(other), {
                COMMANDS.split(',').map(panel_core::pytext::repr).collect::<Vec<_>>().join(", ")
            }),
        ),
    }
}

/// `--name value` / `--name=value` / bare flags, in order.
struct Options {
    pairs: Vec<(String, Option<String>)>,
    positional: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Self {
        const FLAGS: [&str; 1] = ["--password-stdin"];
        let mut pairs = Vec::new();
        let mut positional = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if let Some((name, value)) = arg.split_once('=').filter(|_| arg.starts_with("--")) {
                pairs.push((name.to_string(), Some(value.to_string())));
            } else if arg.starts_with("--") && FLAGS.contains(&arg.as_str()) {
                pairs.push((arg.clone(), None));
            } else if arg.starts_with("--") {
                pairs.push((arg.clone(), args.get(index + 1).cloned()));
                index += 1;
            } else {
                positional.push(arg.clone());
            }
            index += 1;
        }
        Self { pairs, positional }
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.pairs.iter().rev().find(|(key, _)| key == name).and_then(|(_, value)| value.as_deref())
    }

    fn flag(&self, name: &str) -> bool {
        self.pairs.iter().any(|(key, _)| key == name)
    }

    fn unknown(&self, known: &[&str]) -> Option<String> {
        self.pairs
            .iter()
            .map(|(key, _)| key.clone())
            .chain(self.positional.iter().cloned())
            .find(|key| !known.contains(&key.as_str()))
    }
}

fn required<'a>(prog: &str, options: &'a Options, names: &[&str]) -> Result<Vec<&'a str>, Exit> {
    let missing: Vec<&str> = names.iter().copied().filter(|name| options.value(name).is_none()).collect();
    if !missing.is_empty() {
        return Err(usage(prog, format!("the following arguments are required: {}", missing.join(", "))));
    }
    Ok(names.iter().map(|name| options.value(name).unwrap_or_default()).collect())
}

fn create_admin(
    prog: &str,
    database: &PathBuf,
    options: Options,
    stdin: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Exit {
    if let Some(unknown) = options.unknown(&["--username", "--role", "--password-stdin"]) {
        return usage("cli.py", format!("unrecognized arguments: {unknown}"));
    }
    let mut missing = Vec::new();
    if options.value("--username").is_none() {
        missing.push("--username");
    }
    if !options.flag("--password-stdin") {
        missing.push("--password-stdin");
    }
    if !missing.is_empty() {
        return usage(prog, format!("the following arguments are required: {}", missing.join(", ")));
    }
    let username = options.value("--username").unwrap_or_default().to_string();
    let role = options.value("--role").unwrap_or("owner").to_string();
    if !["owner", "admin", "viewer"].contains(&role.as_str()) {
        return usage(
            prog,
            format!(
                "argument --role: invalid choice: {} (choose from 'owner', 'admin', 'viewer')",
                panel_core::pytext::repr(&role)
            ),
        );
    }
    let mut line = String::new();
    if let Err(error) = stdin.read_line(&mut line) {
        return Exit::Failed(error.to_string());
    }
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        return usage("cli.py", "password is required on stdin");
    }
    let result = (|| -> Result<(), String> {
        let database = Database::open(database).map_err(|error| error.to_string())?;
        panel_core::migrations::apply_migrations(&database).map_err(|error| error.to_string())?;
        Store::new(database).create_admin(&username, &password, &role).map_err(|error| error.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            let _ = writeln!(out, "Administrator {} created.", panel_core::pytext::repr(&username));
            Exit::Ok
        }
        Err(error) => Exit::Failed(error),
    }
}

fn api_key_create(prog: &str, database: &PathBuf, options: Options, out: &mut dyn std::io::Write) -> Exit {
    if let Some(unknown) = options.unknown(&["--name", "--scope", "--expires-days"]) {
        return usage("cli.py", format!("unrecognized arguments: {unknown}"));
    }
    let values = match required(prog, &options, &["--name", "--scope"]) {
        Ok(values) => values,
        Err(exit) => return exit,
    };
    let (name, scope) = (values[0].to_string(), values[1].to_string());
    if !SCOPES.contains(&scope.as_str()) {
        return usage(
            prog,
            format!(
                "argument --scope: invalid choice: {} (choose from {})",
                panel_core::pytext::repr(&scope),
                SCOPES.iter().map(|scope| panel_core::pytext::repr(scope)).collect::<Vec<_>>().join(", ")
            ),
        );
    }
    let expires_days = match options.value("--expires-days") {
        None => None,
        Some(text) => match panel_core::pytext::int_from_str(text) {
            Ok(days) => Some(days),
            Err(_) => {
                return usage(
                    prog,
                    format!("argument --expires-days: invalid int value: {}", panel_core::pytext::repr(text)),
                )
            }
        },
    };
    if expires_days.is_some_and(|days| days < 1) {
        return usage("cli.py", "--expires-days must be positive");
    }
    let database = match Database::open(database) {
        Ok(database) => database,
        Err(error) => return Exit::Failed(error.to_string()),
    };
    let service = ApiKeyService::new(database);
    let keys = match service.list() {
        Ok(keys) => keys,
        Err(error) => return Exit::Failed(error.to_string()),
    };
    if keys.iter().any(|key| key.name == name && key.enabled) {
        return usage(
            "cli.py",
            format!("an enabled API key named {} already exists; revoke it first", panel_core::pytext::repr(&name)),
        );
    }
    use panel_core::clock::Clock as _;
    let expires_at = expires_days.map(|days| panel_core::clock::SystemClock.now() + days * 86400);
    match service.create(&name, &scope, expires_at, &Actor::new(None, "installer"), "127.0.0.1", None) {
        Ok((key, plaintext)) => {
            let line = json!({"id": key.id, "name": key.name, "scope": key.scope, "plaintext": plaintext});
            let _ = writeln!(out, "{}", panel_core::pyjson::dumps_default(&line));
            Exit::Ok
        }
        Err(panel_secrets::api_keys::ApiKeyError::Invalid(message)) => usage("cli.py", message),
        Err(error) => Exit::Failed(error.to_string()),
    }
}

fn master_key_init(prog: &str, options: Options, out: &mut dyn std::io::Write) -> Exit {
    if let Some(unknown) = options.unknown(&["--path"]) {
        return usage("cli.py", format!("unrecognized arguments: {unknown}"));
    }
    let path = match required(prog, &options, &["--path"]) {
        Ok(values) => py_path(values[0]),
        Err(exit) => return exit,
    };
    if std::fs::symlink_metadata(&path).is_ok() {
        return usage("cli.py", format!("{} already exists; refusing to overwrite a master key", path.display()));
    }
    match Keyring::generate().save(&path) {
        Ok(()) => {
            let _ = writeln!(
                out,
                "Master keyring written to {} (mode 0600). Back it up separately from the database.",
                path.display()
            );
            Exit::Ok
        }
        Err(error) => Exit::Failed(error.to_string()),
    }
}

/// The process side of [`run`]: real stdin/stdout, messages on stderr, the exit code.
pub fn main(args: &[String]) -> i32 {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout().lock();
    let exit = run(args, &mut input as &mut dyn std::io::BufRead, &mut output);
    let _ = output.flush();
    match &exit {
        Exit::Ok => {}
        Exit::Usage { prog, message } => {
            eprintln!("usage: {prog} [-h] ...\n{prog}: error: {message}");
        }
        Exit::Failed(message) => eprintln!("Error: {message}"),
    }
    exit.code()
}

/// `panel stage-secret verify SOURCE | stage SOURCE DEST` (`stage_secret.py`): exit 64 with
/// `stage-secret: <message>` on any refusal.
pub fn stage_secret(args: &[String]) -> i32 {
    use panel_secrets::stage_secret::{stage, verify, EXIT_FAILURE};
    let result = match args {
        [command, source] if command == "verify" => verify(source.as_ref()),
        [command, source, destination] if command == "stage" => stage(source.as_ref(), destination.as_ref()),
        _ => {
            eprintln!("usage: stage-secret verify SOURCE | stage SOURCE DEST");
            return EXIT_FAILURE;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("stage-secret: {error}");
            EXIT_FAILURE
        }
    }
}

#[cfg(test)]
fn parse(out: &[u8]) -> serde_json::Value {
    serde_json::from_slice(out).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("panel-web-cli-{}", panel_core::ids::token_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn call(args: &[&str], stdin: &str) -> (Exit, String) {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        let mut input = std::io::Cursor::new(stdin.as_bytes().to_vec());
        let mut out = Vec::new();
        let exit = run(&args, &mut input, &mut out);
        (exit, String::from_utf8(out).unwrap())
    }

    #[test]
    fn create_admin_and_key_like_the_installer() {
        let dir = temp();
        let db = dir.join("panel.db");
        let db = db.to_str().unwrap();
        let (exit, out) = call(
            &["--database", db, "create-admin", "--username", "owner", "--password-stdin"],
            "correct horse battery\r\n",
        );
        assert_eq!((exit, out.as_str()), (Exit::Ok, "Administrator 'owner' created.\n"));
        let (exit, _) = call(&["--database", db, "create-admin", "--username", "x", "--password-stdin"], "\n");
        assert_eq!(exit.code(), 2);
        let (exit, _) = call(&["--database", db, "create-admin", "--username", "x", "--password-stdin"], "short\n");
        assert_eq!(exit.code(), 1);
        let (exit, out) = call(&["--database", db, "api-key-create", "--name", "mcp", "--scope", "admin"], "");
        assert_eq!(exit, Exit::Ok);
        assert!(out.starts_with("{\"id\": 1, \"name\": \"mcp\", \"scope\": \"admin\", \"plaintext\": \"pc_"), "{out}");
        assert!(parse(out.as_bytes())["plaintext"].as_str().unwrap().len() > 50);
        let (exit, _) = call(&["--database", db, "api-key-create", "--name", "mcp", "--scope", "admin"], "");
        assert_eq!(exit.code(), 2);
        let (exit, _) = call(&["--database", db, "api-key-create", "--name", "x", "--scope", "root"], "");
        assert_eq!(exit.code(), 2);
        let (exit, _) =
            call(&["--database", db, "api-key-create", "--name", "x", "--scope", "monitor", "--expires-days", "0"], "");
        assert_eq!(exit.code(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn master_key_init_refuses_to_overwrite() {
        let dir = temp();
        let path = dir.join("master-key");
        let path = path.to_str().unwrap();
        let (exit, out) = call(&["master-key-init", "--path", path], "");
        assert_eq!(exit, Exit::Ok);
        assert_eq!(
            out,
            format!("Master keyring written to {path} (mode 0600). Back it up separately from the database.\n")
        );
        assert!(Keyring::load(path.as_ref()).is_ok());
        assert_eq!(call(&["master-key-init", "--path", path], "").0.code(), 2);
        assert_eq!(call(&["db-status"], "").0.code(), 2);
        assert_eq!(call(&["bogus"], "").0.code(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
