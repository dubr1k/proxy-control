//! Documentation commands exercise the real native parser/config loader without host mutation.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

#[test]
fn every_checked_command_parses_against_the_shipped_cli_and_loads_its_configuration() {
    let root = repository();
    let output = Command::new("python3")
        .arg("-c")
        .arg(
            r#"
import json, pathlib, re, shlex, sys
root = pathlib.Path(sys.argv[1])
files = ['docs/INSTALLER_REFERENCE.ru.md', 'docs/INSTALLER_REFERENCE.en.md', 'docs/guides/INSTALL.ru.md', 'docs/guides/INSTALL.en.md',
         'README.md', 'README.en.md', 'docs/guides/MIERU.ru.md', 'docs/guides/MIERU.en.md', 'docs/guides/PANEL.ru.md', 'docs/guides/PANEL.en.md',
         'docs/UPGRADING.md', 'docs/VALIDATION.md']
commands = []
for name in files:
    text = (root / name).read_text()
    for block in re.findall(r'```[a-z]*\s+installer-check\n(.*?)```', text, re.S):
        for line in block.replace('\\\n', ' ').splitlines():
            if line.strip() and not line.lstrip().startswith('#'):
                commands.append([name, shlex.split(line)])
print(json.dumps(commands))
"#,
        )
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let commands: Vec<(String, Vec<String>)> = serde_json::from_slice(&output.stdout).unwrap();
    let mut parsed_commands = 0;
    let mut loaded_configs = 0;
    for (document, mut arguments) in commands {
        while arguments.first().is_some_and(|argument| argument == "sudo" || argument == "env") {
            arguments.remove(0);
        }
        if arguments.first().is_some_and(|argument| argument == "bash") {
            arguments.remove(0);
        }
        let offset = if arguments.starts_with(&["python3".into(), "-m".into(), "installer.cli".into()]) {
            3
        } else if arguments.first().is_some_and(|argument| {
            Path::new(argument)
                .file_name()
                .is_some_and(|name| name == "install.sh" || name == "proxy-control-installer")
        }) {
            1
        } else {
            continue;
        };
        let mut arguments = arguments[offset..].to_vec();
        if let Some(index) = arguments.iter().position(|argument| argument == "--accept-plan") {
            if arguments.get(index + 1).is_some_and(|value| value == "DIGEST") {
                arguments[index + 1] = "0".repeat(64);
            }
        }
        let result = installer_core::cli::parse(&arguments, 80);
        assert!(result.is_ok(), "{document}: {arguments:?}: {result:?}");
        parsed_commands += 1;
        for pair in arguments.windows(2).filter(|pair| pair[0] == "--config") {
            let path = root.join(&pair[1]);
            let result = installer_core::config::load_config(&path);
            assert!(result.is_ok(), "{document}: {}: {result:?}", path.display());
            loaded_configs += 1;
        }
    }
    assert!(parsed_commands > 0, "no documented installer commands were exercised");
    assert!(loaded_configs > 0, "no documented configuration files were loaded");
}
