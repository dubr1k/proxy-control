//! `urllib.parse.urlsplit` and `urljoin` as the host code uses them: splitting for host checks
//! (`hostname` lower-cased, user info, IPv6 brackets) and resolving a redirect's `Location`.

/// `SplitResult(scheme, netloc, path, query, fragment)`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

const C0_CONTROL_OR_SPACE: &[char] = &[
    '\u{0}', '\u{1}', '\u{2}', '\u{3}', '\u{4}', '\u{5}', '\u{6}', '\u{7}', '\u{8}', '\t', '\n', '\u{b}', '\u{c}',
    '\r', '\u{e}', '\u{f}', '\u{10}', '\u{11}', '\u{12}', '\u{13}', '\u{14}', '\u{15}', '\u{16}', '\u{17}', '\u{18}',
    '\u{19}', '\u{1a}', '\u{1b}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', ' ',
];

/// `urlsplit(url)` (Python 3.12+): leading C0 controls and spaces stripped, tabs and line breaks
/// removed, the scheme lower-cased.
pub fn split(url: &str) -> SplitResult {
    let cleaned: String =
        url.trim_start_matches(C0_CONTROL_OR_SPACE).chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest = cleaned.as_str();
    let mut result = SplitResult::default();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        let first = candidate.chars().next();
        if colon > 0
            && first.is_some_and(|c| c.is_ascii_alphabetic())
            && candidate.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            result.scheme = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        result.netloc = after[..end].to_string();
        rest = &after[end..];
    }
    if let Some((before, fragment)) = rest.split_once('#') {
        result.fragment = fragment.to_string();
        rest = before;
    }
    if let Some((before, query)) = rest.split_once('?') {
        result.query = query.to_string();
        rest = before;
    }
    result.path = rest.to_string();
    result
}

impl SplitResult {
    fn userinfo_and_host(&self) -> (Option<&str>, &str) {
        match self.netloc.rsplit_once('@') {
            Some((info, host)) => (Some(info), host),
            None => (None, self.netloc.as_str()),
        }
    }

    /// `.hostname`: lower-cased, without user info, port or IPv6 brackets; `None` when empty.
    pub fn hostname(&self) -> Option<String> {
        let (_, hostport) = self.userinfo_and_host();
        let host = if let Some(bracketed) = hostport.strip_prefix('[') {
            bracketed.split_once(']').map(|(inside, _)| inside).unwrap_or("")
        } else {
            hostport.split_once(':').map(|(host, _)| host).unwrap_or(hostport)
        };
        if host.is_empty() {
            None
        } else {
            Some(host.to_lowercase())
        }
    }

    /// `.username`.
    pub fn username(&self) -> Option<&str> {
        let (info, _) = self.userinfo_and_host();
        info.map(|info| info.split_once(':').map(|(user, _)| user).unwrap_or(info))
    }

    /// `.password`.
    pub fn password(&self) -> Option<&str> {
        let (info, _) = self.userinfo_and_host();
        info.and_then(|info| info.split_once(':').map(|(_, password)| password))
    }

    /// `geturl()`-style reassembly.
    pub fn unsplit(&self) -> String {
        let mut out = String::new();
        if !self.scheme.is_empty() {
            out.push_str(&self.scheme);
            out.push(':');
        }
        if !self.netloc.is_empty() || self.scheme == "https" || self.scheme == "http" {
            out.push_str("//");
            out.push_str(&self.netloc);
        }
        out.push_str(&self.path);
        if !self.query.is_empty() {
            out.push('?');
            out.push_str(&self.query);
        }
        if !self.fragment.is_empty() {
            out.push('#');
            out.push_str(&self.fragment);
        }
        out
    }
}

/// `urljoin(base, reference)` for HTTP(S) URLs (RFC 3986 §5.2 with dot-segment removal).
pub fn join(base: &str, reference: &str) -> String {
    if reference.is_empty() {
        return base.to_string();
    }
    let base_parts = split(base);
    let mut target = split(reference);
    if !target.scheme.is_empty() && target.scheme != base_parts.scheme {
        return target.unsplit();
    }
    target.scheme = base_parts.scheme.clone();
    if reference.trim_start_matches(C0_CONTROL_OR_SPACE).starts_with("//")
        || (!target.netloc.is_empty() && reference.contains("://"))
    {
        target.path = remove_dot_segments(&target.path);
        return target.unsplit();
    }
    target.netloc = base_parts.netloc.clone();
    if target.path.is_empty() {
        target.path = base_parts.path.clone();
        if target.query.is_empty() && !reference.contains('?') {
            target.query = base_parts.query.clone();
        }
        return target.unsplit();
    }
    let merged = if target.path.starts_with('/') {
        target.path.clone()
    } else {
        match base_parts.path.rfind('/') {
            Some(slash) => format!("{}{}", &base_parts.path[..=slash], target.path),
            None => format!("/{}", target.path),
        }
    };
    target.path = remove_dot_segments(&merged);
    target.unsplit()
}

fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len().saturating_sub(1);
    for (index, segment) in segments.iter().enumerate() {
        match *segment {
            "." => {
                if index == last {
                    output.push("");
                }
            }
            ".." => {
                if output.len() > 1 {
                    output.pop();
                }
                if index == last {
                    output.push("");
                }
            }
            other => output.push(other),
        }
    }
    let joined = output.join("/");
    if path.starts_with('/') && !joined.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_matches_urllib() {
        let parts = split("HTTPS://User:Pw@GitHub.com:8443/a/b?x=1#frag");
        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.netloc, "User:Pw@GitHub.com:8443");
        assert_eq!(parts.path, "/a/b");
        assert_eq!(parts.query, "x=1");
        assert_eq!(parts.fragment, "frag");
        assert_eq!(parts.hostname().as_deref(), Some("github.com"));
        assert_eq!(parts.username(), Some("User"));
        assert_eq!(parts.password(), Some("Pw"));
        assert_eq!(split("https://[::1]:443/x").hostname().as_deref(), Some("::1"));
        assert_eq!(split("https:///x").hostname(), None);
        assert_eq!(split(" https://h/\tp").path, "/p");
        assert_eq!(split("1http://x").scheme, "");
        assert_eq!(split("https://github.com").path, "");
    }

    #[test]
    fn join_resolves_redirect_locations() {
        let base = "https://api.github.com/repos/a/b/releases?per_page=10";
        assert_eq!(
            join(base, "https://objects.githubusercontent.com/x?sig=1"),
            "https://objects.githubusercontent.com/x?sig=1"
        );
        assert_eq!(join(base, "/other"), "https://api.github.com/other");
        assert_eq!(join(base, "//github.com/y"), "https://github.com/y");
        assert_eq!(join(base, "next"), "https://api.github.com/repos/a/b/next");
        assert_eq!(join(base, "../up"), "https://api.github.com/repos/a/up");
        assert_eq!(join(base, "?page=2"), "https://api.github.com/repos/a/b/releases?page=2");
        assert_eq!(join(base, "http://github.com/z"), "http://github.com/z");
    }
}
