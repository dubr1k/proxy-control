//! The read-only part of `installer/adapters/nginx.py` the audit needs: the `nginx -T`
//! tokenizer, the stream-context and include tracing, the `map`/`server` parser and the
//! selection of the effective SSL-preread route (`parse_effective_nginx`, `select_route_target`).
//! Positions (`start`, `end`) are code-point offsets into the text, as Python's `str` indices.
//!
//! The Nginx adapter (host WP5a) reuses this module for its own planning; the mutating parts
//! (`patch_owned_map`, `remove_owned_map_block`, rendering) stay with the adapter.
//!
//! Difference from Python (DIFFERENCES.md): a `listen` port and a literal backend port are ASCII
//! digits only (Python's `isdigit`/`\d` also took other Unicode digits and could crash in `int`).

use std::collections::{BTreeMap, BTreeSet};

use crate::pystr::is_space;

/// `TopologyError`: the effective Nginx stream route cannot be selected safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyError(pub String);

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TopologyError {}

type Result<T> = std::result::Result<T, TopologyError>;

fn fail<T>(message: &str) -> Result<T> {
    Err(TopologyError(message.into()))
}

/// One `key value;` line of a map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRoute {
    pub key: String,
    pub value: String,
    pub start: usize,
}

/// `map $source $variable { … }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxMap {
    pub source_variable: String,
    pub variable: String,
    pub source_file: String,
    pub routes: Vec<MapRoute>,
    pub start: usize,
    pub end: usize,
}

/// A `server { … }` block (its listeners, `ssl_preread` and `proxy_pass` values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamServer {
    pub source_file: String,
    pub listener_ports: Vec<u32>,
    pub ssl_preread: Option<String>,
    pub proxy_passes: Vec<String>,
}

/// What `parse_effective_nginx` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxTopology {
    pub maps: Vec<NginxMap>,
    pub servers: Vec<StreamServer>,
    pub stream_enabled: bool,
    pub stream_includes: Vec<String>,
}

/// The one effective map behind the active listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    pub variable: String,
    pub source_variable: String,
    pub source_file: String,
    pub routes: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct Token {
    value: String,
    source_file: String,
    start: usize,
    end: usize,
}

const EFFECTIVE: &str = "<effective>";
const MARKER: &str = "# configuration file ";

/// `parse_effective_nginx(text)`: stream contexts of `nginx -T` and the files they include.
pub fn parse_effective_nginx(text: &str) -> Result<NginxTopology> {
    let tokens = tokenize(text)?;
    let (ranges, included, patterns) = stream_context(&tokens)?;
    let accepted = |index: usize| {
        ranges.iter().any(|(start, end)| *start <= index && index < *end)
            || included.contains(&tokens[index].source_file)
    };
    let parsed = parse_tokens(&tokens, &accepted, !ranges.is_empty())?;
    Ok(NginxTopology { stream_includes: patterns, ..parsed })
}

/// `_parse_file_nginx(text)`: every `map` and `server` of one file, wherever they are.
pub fn parse_file_nginx(text: &str) -> Result<NginxTopology> {
    let tokens = tokenize(text)?;
    parse_tokens(&tokens, &|_| true, false)
}

fn parse_tokens(tokens: &[Token], accepts: &dyn Fn(usize) -> bool, stream_enabled: bool) -> Result<NginxTopology> {
    let mut maps = Vec::new();
    let mut servers = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if accepts(index) && token.value == "map" && index + 3 < tokens.len() {
            if let Some((mapping, next)) = parse_map(tokens, index)? {
                maps.push(mapping);
                index = next;
                continue;
            }
        }
        if accepts(index) && token.value == "server" && index + 1 < tokens.len() && tokens[index + 1].value == "{" {
            let (server, next) = parse_server(tokens, index)?;
            servers.push(server);
            index = next;
            continue;
        }
        index += 1;
    }
    Ok(NginxTopology { maps, servers, stream_enabled, stream_includes: Vec::new() })
}

type StreamContext = (Vec<(usize, usize)>, BTreeSet<String>, Vec<String>);

fn stream_context(tokens: &[Token]) -> Result<StreamContext> {
    let mut ranges = Vec::new();
    let mut patterns: BTreeSet<String> = BTreeSet::new();
    let mut stream_sources: BTreeSet<String> = BTreeSet::new();
    for index in 0..tokens.len().saturating_sub(1) {
        if tokens[index].value != "stream" || tokens[index + 1].value != "{" {
            continue;
        }
        stream_sources.insert(tokens[index].source_file.clone());
        let close = matching_close(tokens, index + 1)?;
        ranges.push((index + 2, close));
        let mut cursor = index + 2;
        while cursor < close {
            if tokens[cursor].value == "include" && cursor + 2 < close && tokens[cursor + 2].value == ";" {
                patterns.insert(normalize_include_pattern(&tokens[cursor + 1].value)?);
                cursor += 3;
                continue;
            }
            cursor += 1;
        }
    }
    let sources: BTreeSet<String> =
        tokens.iter().filter(|token| token.source_file != EFFECTIVE).map(|token| token.source_file.clone()).collect();
    let mut included: BTreeSet<String> = BTreeSet::new();
    loop {
        let others: BTreeSet<String> = sources.difference(&stream_sources).cloned().collect();
        let relative_prefix = relative_include_prefix(&others, &patterns)?;
        let mut expanded = BTreeSet::new();
        for source in &sources {
            for pattern in &patterns {
                if source_matches_include(source, pattern, relative_prefix.as_deref())? {
                    expanded.insert(source.clone());
                    break;
                }
            }
        }
        let new_sources: BTreeSet<String> = expanded.difference(&included).cloned().collect();
        if new_sources.is_empty() {
            break;
        }
        included.extend(new_sources.iter().cloned());
        for index in 0..tokens.len().saturating_sub(2) {
            let token = &tokens[index];
            if new_sources.contains(&token.source_file)
                && tokens[index + 1].source_file == token.source_file
                && tokens[index + 2].source_file == token.source_file
                && token.value == "include"
                && tokens[index + 2].value == ";"
            {
                patterns.insert(normalize_include_pattern(&tokens[index + 1].value)?);
            }
        }
    }
    Ok((ranges, included, patterns.into_iter().collect()))
}

/// `PurePosixPath(path).parts`: the root (`/`, or `//` for exactly two leading slashes) and the
/// non-empty components other than `.`.
pub fn posix_parts(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let rest = if path.starts_with("//") && !path.starts_with("///") {
        parts.push("//".to_string());
        &path[2..]
    } else if path.starts_with('/') {
        parts.push("/".to_string());
        path.trim_start_matches('/')
    } else {
        path
    };
    parts.extend(rest.split('/').filter(|part| !part.is_empty() && *part != ".").map(str::to_string));
    parts
}

/// `str(PurePosixPath(*parts))`.
fn join_parts(parts: &[String]) -> String {
    match parts.first().map(String::as_str) {
        None => ".".into(),
        Some(root @ ("/" | "//")) => format!("{root}{}", parts[1..].join("/")),
        Some(_) => parts.join("/"),
    }
}

/// `_normalize_include_pattern`: `.`/`..` resolved lexically; `..` above an absolute root is an
/// error.
pub fn normalize_include_pattern(pattern: &str) -> Result<String> {
    let absolute = pattern.starts_with('/');
    let mut parts: Vec<String> = Vec::new();
    for part in posix_parts(pattern) {
        if part.is_empty() || part == "/" || part == "." {
            continue;
        }
        if part == ".." {
            if parts.last().is_some_and(|last| last != "..") {
                parts.pop();
            } else if absolute {
                return fail("Nginx include escapes its prefix");
            } else {
                parts.push(part);
            }
            continue;
        }
        parts.push(part);
    }
    let normalized = parts.join("/");
    Ok(if absolute { format!("/{normalized}") } else { normalized })
}

/// `_resolve_include(pattern, prefix)`.
pub fn resolve_include(pattern: &str, prefix: &str) -> Result<String> {
    if pattern.starts_with('/') {
        return normalize_include_pattern(pattern);
    }
    if !prefix.starts_with('/') {
        return fail("Nginx prefix is not absolute");
    }
    normalize_include_pattern(&format!("{}/{pattern}", prefix.trim_end_matches('/')))
}

/// `fnmatch.fnmatchcase(name, pattern)`: `*`, `?`, `[seq]`, `[!seq]` (ranges `a-z`); an
/// unclosed `[` is literal.
pub fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    glob(&name, &pattern)
}

enum Item {
    Any,
    One,
    Literal(char),
    Class { negate: bool, members: Vec<(char, char)> },
}

fn glob_items(pattern: &[char]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        let c = pattern[i];
        i += 1;
        match c {
            '*' => {
                if !matches!(items.last(), Some(Item::Any)) {
                    items.push(Item::Any);
                }
            }
            '?' => items.push(Item::One),
            '[' => {
                let mut j = i;
                if j < pattern.len() && pattern[j] == '!' {
                    j += 1;
                }
                if j < pattern.len() && pattern[j] == ']' {
                    j += 1;
                }
                while j < pattern.len() && pattern[j] != ']' {
                    j += 1;
                }
                if j >= pattern.len() {
                    items.push(Item::Literal('['));
                    continue;
                }
                let stuff = &pattern[i..j];
                i = j + 1;
                let (negate, body) = match stuff.first() {
                    Some('!') => (true, &stuff[1..]),
                    _ => (false, stuff),
                };
                let mut members = Vec::new();
                let mut k = 0;
                while k < body.len() {
                    if k + 2 < body.len() && body[k + 1] == '-' {
                        if body[k] <= body[k + 2] {
                            members.push((body[k], body[k + 2]));
                        }
                        k += 3;
                    } else {
                        members.push((body[k], body[k]));
                        k += 1;
                    }
                }
                items.push(Item::Class { negate, members });
            }
            c => items.push(Item::Literal(c)),
        }
    }
    items
}

fn glob(name: &[char], pattern: &[char]) -> bool {
    let items = glob_items(pattern);
    fn step(name: &[char], items: &[Item]) -> bool {
        match items.first() {
            None => name.is_empty(),
            Some(Item::Any) => (0..=name.len()).rev().any(|skip| step(&name[skip..], &items[1..])),
            Some(item) => {
                let Some(c) = name.first() else { return false };
                let ok = match item {
                    Item::One => true,
                    Item::Literal(expected) => c == expected,
                    Item::Class { negate, members } => {
                        members.iter().any(|(low, high)| low <= c && c <= high) != *negate
                    }
                    Item::Any => unreachable!(),
                };
                ok && step(&name[1..], &items[1..])
            }
        }
    }
    step(name, &items)
}

/// `_glob_path_matches(path, pattern)`: the same number of parts, each matching.
pub fn glob_path_matches(path: &str, pattern: &str) -> bool {
    let path_parts = posix_parts(path);
    let pattern_parts = posix_parts(pattern);
    path_parts.len() == pattern_parts.len()
        && path_parts.iter().zip(&pattern_parts).all(|(part, pattern)| fnmatchcase(part, pattern))
}

fn relative_include_prefix(sources: &BTreeSet<String>, patterns: &BTreeSet<String>) -> Result<Option<String>> {
    let mut candidates = BTreeSet::new();
    for pattern in patterns.iter().filter(|pattern| !pattern.starts_with('/')) {
        for source in sources {
            if let Some(candidate) = relative_prefix_candidate(source, pattern) {
                candidates.insert(candidate);
            }
        }
    }
    if candidates.len() > 1 {
        return fail("relative Nginx include prefix is ambiguous");
    }
    Ok(candidates.into_iter().next())
}

fn relative_prefix_candidate(source: &str, pattern: &str) -> Option<String> {
    let pattern_parts = posix_parts(pattern);
    if pattern_parts.is_empty() || pattern_parts.iter().any(|part| part == "..") {
        return None;
    }
    let source_parts = posix_parts(source);
    if source_parts.len() <= pattern_parts.len() {
        return None;
    }
    let split = source_parts.len() - pattern_parts.len();
    if !source_parts[split..].iter().zip(&pattern_parts).all(|(part, pattern)| fnmatchcase(part, pattern)) {
        return None;
    }
    Some(join_parts(&source_parts[..split]))
}

fn source_matches_include(source: &str, pattern: &str, relative_prefix: Option<&str>) -> Result<bool> {
    if pattern.starts_with('/') {
        return Ok(glob_path_matches(source, pattern));
    }
    match relative_prefix {
        None => Ok(false),
        Some(prefix) => Ok(glob_path_matches(source, &resolve_include(pattern, prefix)?)),
    }
}

/// `_VARIABLE.fullmatch`: `$` + `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_variable(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('$') else { return false };
    let mut chars = rest.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `select_route_target(topology, listener_port)`: trace an active SSL-preread listener to its
/// one effective map.
pub fn select_route_target(topology: &NginxTopology, listener_port: u32) -> Result<RouteTarget> {
    let active: Vec<&StreamServer> =
        topology.servers.iter().filter(|server| server.listener_ports.contains(&listener_port)).collect();
    if active.is_empty() {
        return Err(TopologyError(format!("no effective stream listener on port {listener_port}")));
    }
    let mut variables = BTreeSet::new();
    for server in &active {
        if server.ssl_preread.as_deref() != Some("on") || server.proxy_passes.len() != 1 {
            return fail("active stream route is dynamic or unresolved");
        }
        let proxy_pass = &server.proxy_passes[0];
        if !is_variable(proxy_pass) {
            return fail("active stream route is dynamic or unresolved");
        }
        variables.insert(proxy_pass.clone());
    }
    if variables.len() != 1 {
        return fail("more than one effective map feeds the active listener");
    }
    let variable = variables.into_iter().next().expect("one variable");
    let matches: Vec<&NginxMap> = topology.maps.iter().filter(|mapping| mapping.variable == variable).collect();
    if matches.len() != 1 {
        if matches.len() > 1 {
            return fail("more than one effective map feeds the active listener");
        }
        return fail("active stream route is dynamic or unresolved");
    }
    let mapping = matches[0];
    if mapping.source_variable != "$ssl_preread_server_name" {
        return fail("active stream route is dynamic or unresolved");
    }
    if mapping.routes.iter().any(|route| !literal_backend(&route.value)) {
        return fail("active stream route is dynamic or unresolved");
    }
    Ok(RouteTarget {
        variable: mapping.variable.clone(),
        source_variable: mapping.source_variable.clone(),
        source_file: mapping.source_file.clone(),
        routes: mapping.routes.iter().map(|route| (route.key.clone(), route.value.clone())).collect(),
    })
}

/// `_SOURCE_MARKER.match(text, index)`: the path and the index after the marker.
fn source_marker(chars: &[char], index: usize) -> Option<(String, usize)> {
    let marker: Vec<char> = MARKER.chars().collect();
    if chars.len() < index + marker.len() || chars[index..index + marker.len()] != marker[..] {
        return None;
    }
    let start = index + marker.len();
    if chars.get(start) != Some(&'/') {
        return None;
    }
    let mut end = start + 1;
    while end < chars.len() && !matches!(chars[end], ':' | '\r' | '\n') {
        end += 1;
    }
    if chars.get(end) != Some(&':') {
        return None;
    }
    let after = end + 1;
    let next = match (chars.get(after), chars.get(after + 1)) {
        (None, _) => after,
        (Some('\n'), _) => after + 1,
        (Some('\r'), Some('\n')) => after + 2,
        _ => return None,
    };
    Some((chars[start..end].iter().collect(), next))
}

fn tokenize(text: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut source_file = EFFECTIVE.to_string();
    let mut index = 0;
    let mut line_start = true;
    let mut depth: i64 = 0;
    while index < chars.len() {
        if line_start {
            if let Some((path, next)) = source_marker(&chars, index) {
                if depth != 0 {
                    return fail("Nginx source marker is embedded within a configuration block");
                }
                source_file = path;
                index = next;
                line_start = true;
                continue;
            }
        }
        let c = chars[index];
        if matches!(c, ' ' | '\t' | '\r') {
            index += 1;
            continue;
        }
        if c == '\n' {
            index += 1;
            line_start = true;
            continue;
        }
        if c == '#' {
            index = match chars[index..].iter().position(|c| *c == '\n') {
                Some(offset) => index + offset + 1,
                None => chars.len(),
            };
            line_start = true;
            continue;
        }
        line_start = false;
        if matches!(c, '{' | '}' | ';') {
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                if depth < 0 {
                    return fail("unbalanced Nginx configuration block");
                }
            }
            tokens.push(Token { value: c.to_string(), source_file: source_file.clone(), start: index, end: index + 1 });
            index += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            let start = index;
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < chars.len() {
                let c2 = chars[index];
                if c2 == '\\' && index + 1 < chars.len() {
                    value.push(chars[index + 1]);
                    index += 2;
                    continue;
                }
                if c2 == c {
                    index += 1;
                    closed = true;
                    break;
                }
                value.push(c2);
                index += 1;
            }
            if !closed {
                return fail("unterminated quoted Nginx token");
            }
            tokens.push(Token { value, source_file: source_file.clone(), start, end: index });
            continue;
        }
        let start = index;
        while index < chars.len() && !" \t\r\n{};#'\"".contains(chars[index]) {
            index += 1;
        }
        tokens.push(Token {
            value: chars[start..index].iter().collect(),
            source_file: source_file.clone(),
            start,
            end: index,
        });
    }
    if depth != 0 {
        return fail("unbalanced Nginx configuration block");
    }
    Ok(tokens)
}

fn parse_map(tokens: &[Token], start: usize) -> Result<Option<(NginxMap, usize)>> {
    if tokens[start + 3].value != "{" {
        return Ok(None);
    }
    let source_variable = &tokens[start + 1].value;
    let variable = &tokens[start + 2].value;
    if !is_variable(source_variable) || !is_variable(variable) {
        return Ok(None);
    }
    let close = matching_close(tokens, start + 3)?;
    let mut routes = Vec::new();
    let mut current: Vec<&Token> = Vec::new();
    let mut depth = 1;
    for token in &tokens[start + 4..close] {
        match token.value.as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            ";" if depth == 1 => {
                if current.len() >= 2 {
                    let value: Vec<&str> = current[1..].iter().map(|item| item.value.as_str()).collect();
                    routes.push(MapRoute {
                        key: current[0].value.clone(),
                        value: value.join(" "),
                        start: current[0].start,
                    });
                }
                current.clear();
            }
            _ if depth == 1 => current.push(token),
            _ => {}
        }
    }
    if !current.is_empty() {
        return fail("unterminated directive in Nginx map");
    }
    Ok(Some((
        NginxMap {
            source_variable: source_variable.clone(),
            variable: variable.clone(),
            source_file: tokens[start].source_file.clone(),
            routes,
            start: tokens[start].start,
            end: tokens[close].end,
        },
        close + 1,
    )))
}

fn parse_server(tokens: &[Token], start: usize) -> Result<(StreamServer, usize)> {
    let close = matching_close(tokens, start + 1)?;
    let mut directives: Vec<Vec<&str>> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut depth = 1;
    for token in &tokens[start + 2..close] {
        match token.value.as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            ";" if depth == 1 => {
                if !current.is_empty() {
                    directives.push(std::mem::take(&mut current));
                }
                current.clear();
            }
            value if depth == 1 => current.push(value),
            _ => {}
        }
    }
    let mut listeners = BTreeSet::new();
    let mut ssl_preread = None;
    let mut proxy_passes = Vec::new();
    for directive in &directives {
        match directive[0] {
            "listen" if directive.len() >= 2 => {
                if let Some(port) = listen_port(directive[1]) {
                    listeners.insert(port);
                }
            }
            "ssl_preread" if directive.len() == 2 => ssl_preread = Some(directive[1].to_string()),
            "proxy_pass" if directive.len() >= 2 => proxy_passes.push(directive[1..].join(" ")),
            _ => {}
        }
    }
    Ok((
        StreamServer {
            source_file: tokens[start].source_file.clone(),
            listener_ports: listeners.into_iter().collect(),
            ssl_preread,
            proxy_passes,
        },
        close + 1,
    ))
}

fn matching_close(tokens: &[Token], opening: usize) -> Result<usize> {
    let mut depth = 0i64;
    for (index, token) in tokens.iter().enumerate().skip(opening) {
        if token.value == "{" {
            depth += 1;
        } else if token.value == "}" {
            depth -= 1;
            if depth == 0 {
                return Ok(index);
            }
        }
    }
    fail("unterminated Nginx block")
}

/// ASCII digits as a port number, `None` beyond 65535 (or empty).
fn port_number(digits: &str) -> Option<u32> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    if trimmed.len() > 5 {
        return None;
    }
    let value: u32 = if trimmed.is_empty() { 0 } else { trimmed.parse().ok()? };
    (value <= 65535).then_some(value)
}

/// `_listen_port`: `unix:` sockets have none; a bare number or the digits after the last `:`.
fn listen_port(value: &str) -> Option<u32> {
    if value.starts_with("unix:") {
        return None;
    }
    let digits = if value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty() {
        value
    } else {
        let (_, tail) = value.rsplit_once(':')?;
        tail
    };
    port_number(digits).filter(|port| (1..=65535).contains(port))
}

/// `_literal_backend`: `host:port`, `[v6]:port` or `unix:/path`, no variables or spaces.
pub fn literal_backend(value: &str) -> bool {
    if value.contains('$') || value.chars().any(is_space) {
        return false;
    }
    if value.starts_with("unix:/") {
        return !value.contains('\0') && value.chars().count() > "unix:/".len();
    }
    let port = if let Some(rest) = value.strip_prefix('[') {
        let Some(close) = rest.find(']') else { return false };
        let inside = &rest[..close];
        if inside.is_empty() || !inside.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return false;
        }
        let Some(port) = rest[close + 1..].strip_prefix(':') else { return false };
        port
    } else {
        let Some((host, port)) = value.split_once(':') else { return false };
        let bytes = host.as_bytes();
        let ok = !bytes.is_empty()
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-');
        if !ok {
            return false;
        }
        port
    };
    port_number(port).is_some_and(|port| (1..=65535).contains(&port))
}

/// Every SNI map of a topology keyed by its file, for callers that count them.
pub fn map_files(topology: &NginxTopology, source_variable: &str) -> BTreeMap<String, usize> {
    let mut files = BTreeMap::new();
    for mapping in topology.maps.iter().filter(|mapping| mapping.source_variable == source_variable) {
        if mapping.source_file != EFFECTIVE {
            *files.entry(mapping.source_file.clone()).or_insert(0) += 1;
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &str = "# configuration file /etc/nginx/nginx.conf:\n\
        events {}\nstream {\n  include /etc/nginx/stream.d/*.conf;\n  server { listen 443; ssl_preread on; proxy_pass $upstream; }\n}\n\
        # configuration file /etc/nginx/stream.d/routes.conf:\n\
        map $ssl_preread_server_name $upstream {\n  a.example.com 127.0.0.1:8443;\n  default 127.0.0.1:10443;\n}\n";

    #[test]
    fn included_stream_file_feeds_the_listener() {
        let topology = parse_effective_nginx(STREAM).unwrap();
        assert!(topology.stream_enabled);
        assert_eq!(topology.stream_includes, vec!["/etc/nginx/stream.d/*.conf".to_string()]);
        let target = select_route_target(&topology, 443).unwrap();
        assert_eq!(target.source_file, "/etc/nginx/stream.d/routes.conf");
        assert_eq!(target.routes[0], ("a.example.com".into(), "127.0.0.1:8443".into()));
        assert_eq!(select_route_target(&topology, 8443).unwrap_err().0, "no effective stream listener on port 8443");
    }

    #[test]
    fn tokenizer_errors_match_python() {
        assert_eq!(parse_effective_nginx("a { b;").unwrap_err().0, "unbalanced Nginx configuration block");
        assert_eq!(parse_effective_nginx("}").unwrap_err().0, "unbalanced Nginx configuration block");
        assert_eq!(parse_effective_nginx("a \"b").unwrap_err().0, "unterminated quoted Nginx token");
        assert_eq!(
            parse_effective_nginx("a {\n# configuration file /x:\n}").unwrap_err().0,
            "Nginx source marker is embedded within a configuration block"
        );
        assert_eq!(parse_file_nginx("map $a $b { x y }").unwrap_err().0, "unterminated directive in Nginx map");
        assert_eq!(normalize_include_pattern("/../x").unwrap_err().0, "Nginx include escapes its prefix");
    }

    #[test]
    fn paths_and_globs_follow_python() {
        assert_eq!(posix_parts("/etc//nginx/./x"), vec!["/", "etc", "nginx", "x"]);
        assert_eq!(posix_parts("//a"), vec!["//", "a"]);
        assert_eq!(normalize_include_pattern("a/../../b/./c").unwrap(), "../b/c");
        assert_eq!(normalize_include_pattern("/etc/nginx/../x").unwrap(), "/etc/x");
        assert_eq!(resolve_include("stream.d/*.conf", "/etc/nginx/").unwrap(), "/etc/nginx/stream.d/*.conf");
        assert!(resolve_include("x", "rel").is_err());
        assert!(fnmatchcase("routes.conf", "*.conf"));
        assert!(fnmatchcase("a1", "a[0-9]"));
        assert!(!fnmatchcase("a1", "a[!0-9]"));
        assert!(fnmatchcase("[x", "[x"));
        assert!(!fnmatchcase("Routes.conf", "r*"));
        assert!(glob_path_matches("/etc/nginx/x.conf", "/etc/*/x.conf"));
        assert!(!glob_path_matches("/etc/nginx/a/x.conf", "/etc/*/x.conf"));
    }

    #[test]
    fn relative_includes_resolve_against_the_one_prefix() {
        let text = "# configuration file /etc/nginx/nginx.conf:\nstream { include streams/*.conf; }\n\
            # configuration file /etc/nginx/streams/r.conf:\nserver { listen 443; ssl_preread on; proxy_pass $u; }\n\
            map $ssl_preread_server_name $u { x.example.com 127.0.0.1:1; }\n";
        let topology = parse_effective_nginx(text).unwrap();
        assert_eq!(topology.servers.len(), 1);
        assert_eq!(select_route_target(&topology, 443).unwrap().variable, "$u");
    }

    #[test]
    fn backends_and_listeners() {
        assert!(literal_backend("127.0.0.1:8443"));
        assert!(literal_backend("[::1]:8443"));
        assert!(literal_backend("unix:/run/x.sock"));
        assert!(!literal_backend("unix:/"));
        assert!(!literal_backend("$backend"));
        assert!(!literal_backend("host:0"));
        assert!(!literal_backend("host:65536"));
        assert!(!literal_backend("-host:1"));
        assert_eq!(listen_port("443"), Some(443));
        assert_eq!(listen_port("[::]:443"), Some(443));
        assert_eq!(listen_port("unix:/x"), None);
        assert_eq!(listen_port("0"), None);
        assert_eq!(listen_port("443 ssl"), None);
    }
}
