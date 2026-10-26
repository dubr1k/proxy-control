//! `StaticFiles(directory=panel/static)` (html off) behind `Mount("/static")`, with Starlette's
//! `FileResponse`: the content type from Python's built-in `mimetypes` table (`text/javascript;
//! charset=utf-8` for `.js`), `accept-ranges`, `content-length`, `last-modified` and the md5 etag of
//! `"<st_mtime>-<st_size>"`; `If-None-Match`/`If-Modified-Since` → 304; `Range` → 206 (one range,
//! or `multipart/byteranges`), 400 for a malformed header, 416 when unsatisfiable; any method but
//! GET/HEAD → 405 (no `Allow`); a path that leaves the directory, a directory or a missing file → 404.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use axum::body::Body;
use axum::response::Response;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method};

use super::mime_table::{ENCODINGS_MAP, SUFFIX_MAP, TYPES_MAP};
use super::request::latin1;
use super::response;
use crate::state::AppState;

fn detail(code: u16, text: &str) -> Response {
    response::json(code, &serde_json::json!({"detail": text}))
}

/// Serves `relative` (the mount's `path` parameter, decoded) from the static directory.
pub async fn serve(state: &AppState, method: &Method, headers: &HeaderMap, relative: &str) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return detail(405, "Method Not Allowed");
    }
    let directory = state.static_dir.clone();
    let relative = relative.to_string();
    let found = tokio::task::spawn_blocking(move || lookup(&directory, &relative)).await;
    let (path, info) = match found {
        Ok(Lookup::File(path, info)) => (path, info),
        Ok(Lookup::NotFound) => return detail(404, "Not Found"),
        Ok(Lookup::Forbidden) => return detail(401, "Unauthorized"),
        Ok(Lookup::Failed(error)) => {
            eprintln!("ERROR static file lookup failed: {error}");
            return response::unhandled();
        }
        Err(error) => {
            eprintln!("ERROR static file lookup failed: {error}");
            return response::unhandled();
        }
    };
    file_response(method, headers, &path, &info).await
}

enum Lookup {
    File(PathBuf, Metadata),
    NotFound,
    Forbidden,
    Failed(std::io::Error),
}

/// `os.path.normpath(os.path.join(*route_path.split("/")))`: `.` and empty parts dropped, `..`
/// eats the previous part (kept at the start).
fn normpath(relative: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

/// `StaticFiles.lookup_path` + the regular-file check.
fn lookup(directory: &Path, relative: &str) -> Lookup {
    let normal = normpath(relative);
    if normal.contains('\0') {
        return Lookup::NotFound;
    }
    let joined = directory.join(&normal);
    let root = match std::fs::canonicalize(directory) {
        Ok(root) => root,
        Err(error) => return Lookup::Failed(error),
    };
    let full = match std::fs::canonicalize(&joined) {
        Ok(full) => full,
        Err(error) => return io_lookup(error),
    };
    if !full.starts_with(&root) || full.components().any(|part| matches!(part, Component::ParentDir)) {
        return Lookup::NotFound;
    }
    match std::fs::metadata(&full) {
        Ok(info) if info.is_file() => Lookup::File(full, info),
        Ok(_) => Lookup::NotFound,
        Err(error) => io_lookup(error),
    }
}

fn io_lookup(error: std::io::Error) -> Lookup {
    match error.raw_os_error() {
        Some(libc_enoent) if libc_enoent == 2 || libc_enoent == 20 || libc_enoent == 36 => Lookup::NotFound,
        Some(13) | Some(1) => Lookup::Forbidden,
        _ if error.kind() == std::io::ErrorKind::InvalidInput => Lookup::NotFound,
        _ => Lookup::Failed(error),
    }
}

/// `mimetypes.guess_type(path)[0]` with Python's built-in tables.
pub fn guess_type(path: &str) -> Option<&'static str> {
    let lookup = |table: &'static [(&str, &str)], key: &str| {
        table.binary_search_by(|(name, _)| (*name).cmp(key)).ok().map(|index| table[index].1)
    };
    // `os.path.splitext`: the last dot of the last component, not leading dots.
    let splitext = |path: &str| -> (String, String) {
        let name_start = path.rfind('/').map_or(0, |index| index + 1);
        let name = &path[name_start..];
        let stripped = name.trim_start_matches('.');
        let leading = name.len() - stripped.len();
        match stripped.rfind('.') {
            Some(dot) => {
                let at = name_start + leading + dot;
                (path[..at].to_string(), path[at..].to_string())
            }
            None => (path.to_string(), String::new()),
        }
    };
    let (mut base, mut ext) = splitext(path);
    while let Some(replacement) = lookup(SUFFIX_MAP, &panel_core::pytext::lower(&ext)) {
        (base, ext) = splitext(&format!("{base}{replacement}"));
    }
    if lookup(ENCODINGS_MAP, &ext).is_some() {
        (_, ext) = splitext(&base);
    }
    lookup(TYPES_MAP, &panel_core::pytext::lower(&ext))
}

/// `str(st_mtime)`: CPython's float of `sec + nsec * 1e-9`, as `repr`.
pub fn mtime_text(info: &Metadata) -> (f64, String) {
    let mtime = info.mtime() as f64 + info.mtime_nsec() as f64 * 1e-9;
    (mtime, panel_core::pyjson::float_repr(mtime))
}

/// Starlette's etag: `"` + md5 hex of `f"{st_mtime}-{st_size}"` + `"`.
pub fn etag(mtime_text: &str, size: u64) -> String {
    use md5::Digest as _;
    let digest = md5::Md5::digest(format!("{mtime_text}-{size}").as_bytes());
    format!("\"{}\"", panel_core::ids::hex(&digest))
}

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `email.utils.formatdate(timeval, usegmt=True)`.
pub fn formatdate(timeval: f64) -> String {
    let seconds = timeval.floor() as i64;
    let days = seconds.div_euclid(86400);
    let rest = seconds.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `email.utils.parsedate`: the 9-tuple's first six fields `(y, m, d, H, M, S)` for the common
/// forms (`Sun, 06 Nov 1994 08:49:37 GMT`, without the weekday, two-digit years); anything else is
/// `None`. The zone is ignored, as `is_not_modified` compares the tuples.
pub fn parsedate(text: &str) -> Option<(i64, u32, u32, u32, u32, u32)> {
    let mut words: Vec<&str> = text.split_whitespace().collect();
    if words.first().is_some_and(|word| word.ends_with(',') || DAYS.iter().any(|day| word.eq_ignore_ascii_case(day))) {
        words.remove(0);
    }
    if words.len() < 4 {
        return None;
    }
    let (mut day, mut month) = (words[0], words[1]);
    if MONTHS.iter().any(|name| day.to_ascii_lowercase().starts_with(&name.to_ascii_lowercase())) {
        std::mem::swap(&mut day, &mut month);
    }
    let month = MONTHS.iter().position(|name| month.len() >= 3 && name.eq_ignore_ascii_case(&month[..3]))? as u32 + 1;
    let day: u32 = day.trim_end_matches(',').parse().ok()?;
    let mut year: i64 = words[2].trim_end_matches(',').parse().ok()?;
    let mut clock: Vec<u32> = Vec::new();
    for part in words[3].split(':') {
        clock.push(part.parse().ok()?);
    }
    let (hour, minute, second) = match clock.as_slice() {
        [h, m] => (*h, *m, 0),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    if year < 100 {
        year += if year > 68 { 1900 } else { 2000 };
    }
    Some((year, month, day, hour, minute, second))
}

fn set(response: &mut Response, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(name, value);
    }
}

struct Stat {
    content_type: String,
    size: u64,
    last_modified: String,
    etag: String,
}

impl Stat {
    fn headers(&self, response: &mut Response) {
        set(response, http::header::CONTENT_TYPE, &self.content_type);
        set(response, http::header::ACCEPT_RANGES, "bytes");
        set(response, http::header::CONTENT_LENGTH, &self.size.to_string());
        set(response, http::header::LAST_MODIFIED, &self.last_modified);
        set(response, http::header::ETAG, &self.etag);
    }
}

async fn file_response(method: &Method, headers: &HeaderMap, path: &Path, info: &Metadata) -> Response {
    let (mtime, mtime_text) = mtime_text(info);
    let media = guess_type(&path.to_string_lossy()).unwrap_or("application/octet-stream");
    let content_type = if media.starts_with("text/") { format!("{media}; charset=utf-8") } else { media.to_string() };
    let stat =
        Stat { content_type, size: info.len(), last_modified: formatdate(mtime), etag: etag(&mtime_text, info.len()) };
    let header = |name: &str| headers.get(name).map(|value| latin1(value.as_bytes()));
    // `StaticFiles.is_not_modified`.
    let not_modified = if let Some(if_none_match) = header("if-none-match").filter(|value| !value.is_empty()) {
        if_none_match.split(',').any(|tag| {
            let tag = panel_core::pytext::strip(tag);
            tag.strip_prefix("W/").unwrap_or(tag) == stat.etag
        })
    } else {
        match (header("if-modified-since").and_then(|value| parsedate(&value)), parsedate(&stat.last_modified)) {
            (Some(since), Some(modified)) => since >= modified,
            _ => false,
        }
    };
    if not_modified {
        let mut answer = response::empty(304);
        set(&mut answer, http::header::ETAG, &stat.etag);
        return answer;
    }
    let head = method == Method::HEAD;
    let range = header("range");
    let use_range = match (&range, header("if-range")) {
        (None, _) => false,
        (Some(_), Some(if_range)) => if_range == stat.last_modified || if_range == stat.etag,
        (Some(_), None) => true,
    };
    if !use_range {
        return whole_file(path, &stat, head).await;
    }
    let ranges = match parse_range_header(range.as_deref().unwrap_or_default(), stat.size) {
        Ok(ranges) => ranges,
        Err(RangeError::Malformed(text)) => return response::plain(400, text),
        Err(RangeError::Unsatisfiable) => {
            let mut answer = response::plain(416, "");
            set(&mut answer, http::header::CONTENT_RANGE, &format!("bytes */{}", stat.size));
            return answer;
        }
    };
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("ERROR static file read failed: {error}");
            return response::unhandled();
        }
    };
    let slice = |start: u64, end: u64| {
        let end = end.min(bytes.len() as u64) as usize;
        bytes[(start as usize).min(end)..end].to_vec()
    };
    match ranges.as_slice() {
        [] => whole_file(path, &stat, head).await,
        [(start, end)] => {
            let body = if head { Vec::new() } else { slice(*start, *end) };
            let mut answer = Response::new(Body::from(body));
            *answer.status_mut() = http::StatusCode::PARTIAL_CONTENT;
            stat.headers(&mut answer);
            set(&mut answer, http::header::CONTENT_RANGE, &format!("bytes {start}-{}/{}", end - 1, stat.size));
            set(&mut answer, http::header::CONTENT_LENGTH, &(end - start).to_string());
            answer
        }
        many => {
            let boundary = panel_core::ids::token_hex(13);
            let mut body = Vec::new();
            for (start, end) in many {
                body.extend_from_slice(
                    format!(
                        "--{boundary}\r\nContent-Type: {}\r\nContent-Range: bytes {start}-{}/{}\r\n\r\n",
                        stat.content_type,
                        end - 1,
                        stat.size
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(&slice(*start, *end));
                body.extend_from_slice(b"\r\n");
            }
            body.extend_from_slice(format!("--{boundary}--").as_bytes());
            let length = body.len();
            let mut answer = Response::new(Body::from(if head { Vec::new() } else { body }));
            *answer.status_mut() = http::StatusCode::PARTIAL_CONTENT;
            stat.headers(&mut answer);
            set(&mut answer, http::header::CONTENT_TYPE, &format!("multipart/byteranges; boundary={boundary}"));
            set(&mut answer, http::header::CONTENT_LENGTH, &length.to_string());
            answer
        }
    }
}

async fn whole_file(path: &Path, stat: &Stat, head: bool) -> Response {
    let body = if head {
        Vec::new()
    } else {
        match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("ERROR static file read failed: {error}");
                return response::unhandled();
            }
        }
    };
    let mut answer = Response::new(Body::from(body));
    stat.headers(&mut answer);
    answer
}

#[derive(Debug, PartialEq)]
enum RangeError {
    Malformed(&'static str),
    Unsatisfiable,
}

/// `FileResponse._parse_range_header`.
fn parse_range_header(header: &str, size: u64) -> Result<Vec<(u64, u64)>, RangeError> {
    let (units, spec) = header.split_once('=').ok_or(RangeError::Malformed("Malformed range header."))?;
    if panel_core::pytext::lower(panel_core::pytext::strip(units)) != "bytes" {
        return Err(RangeError::Malformed("Only support bytes range"));
    }
    if spec.matches(',').count() + 1 > 100 {
        return Ok(Vec::new());
    }
    let mut ranges: Vec<(i128, i128)> = Vec::new();
    for part in spec.split(',') {
        let part = panel_core::pytext::strip(part);
        if part.is_empty() || part == "-" || !part.contains('-') {
            continue;
        }
        let (start_text, end_text) = part.split_once('-').expect("contains '-'");
        let (start_text, end_text) = (panel_core::pytext::strip(start_text), panel_core::pytext::strip(end_text));
        let int = |text: &str| panel_core::pytext::int_from_str(text).ok().map(i128::from);
        let size = i128::from(size);
        let start = if start_text.is_empty() {
            match int(end_text) {
                Some(end) => (size - end).max(0),
                None => continue,
            }
        } else {
            match int(start_text) {
                Some(start) => start,
                None => continue,
            }
        };
        let end = if !start_text.is_empty() && !end_text.is_empty() {
            match int(end_text) {
                Some(end) if end < size => end + 1,
                Some(_) => size,
                None => continue,
            }
        } else {
            size
        };
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Err(RangeError::Malformed("Range header: range must be requested"));
    }
    let size = i128::from(size);
    if ranges.iter().any(|(start, _)| !(0 <= *start && *start < size)) {
        return Err(RangeError::Unsatisfiable);
    }
    if ranges.iter().any(|(start, end)| start >= end) {
        return Err(RangeError::Malformed("Range header: start must be less than end"));
    }
    if ranges.len() > 1 {
        ranges.sort();
        let mut merged = vec![ranges[0]];
        for (start, end) in ranges.into_iter().skip(1) {
            let last = merged.last_mut().expect("non-empty");
            if start <= last.1 {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        ranges = merged;
    }
    Ok(ranges.into_iter().map(|(start, end)| (start as u64, end as u64)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_normalise_like_normpath() {
        assert_eq!(normpath("/"), ".");
        assert_eq!(normpath("/a/./b//c"), "a/b/c");
        assert_eq!(normpath("/../x"), "../x");
        assert_eq!(normpath("/a/../../x"), "../x");
    }

    #[test]
    fn ranges_parse_like_starlette() {
        assert_eq!(parse_range_header("bytes=0-9", 52), Ok(vec![(0, 10)]));
        assert_eq!(parse_range_header("bytes=-5", 52), Ok(vec![(47, 52)]));
        assert_eq!(parse_range_header("bytes=0-4, 10-14, 3-6", 52), Ok(vec![(0, 7), (10, 15)]));
        assert_eq!(parse_range_header("bytes", 52), Err(RangeError::Malformed("Malformed range header.")));
        assert_eq!(parse_range_header("bytes=99-", 52), Err(RangeError::Unsatisfiable));
    }

    #[test]
    fn dates_parse_and_format() {
        assert_eq!(formatdate(1761400000.0), "Sat, 25 Oct 2025 13:46:40 GMT");
        assert_eq!(parsedate("Sat, 25 Oct 2025 13:46:40 GMT"), Some((2025, 10, 25, 13, 46, 40)));
        assert_eq!(parsedate("yesterday"), None);
    }
}
