//! QR codes as python-qrcode 8.2 makes them for the panel (`qrcode.make(link,
//! image_factory=SvgPathImage)`): error correction M, a 4-module quiet zone, 1 mm modules, one SVG
//! `<path>`, byte for byte.
//!
//! The `qrcode` crate provides the standard parts (bit stream, Reed–Solomon codewords, function
//! patterns, data placement, masks, format and version information). What python-qrcode decides
//! its own way is reproduced here:
//!
//! - segmentation (`add_data(optimize=20)`): runs of at least 20 digits become numeric segments,
//!   then runs of at least 20 alphanumeric characters alphanumeric ones, the rest bytes (a payload
//!   of 20 bytes or fewer is one segment of the best mode);
//! - version: the smallest that fits (`best_fit`), over 40 being [`DataOverflow`] (python-qrcode's
//!   version setter raises `ValueError("Invalid version (was 41, expected 1 to 40)")` there);
//! - mask: python-qrcode scores each mask with its own penalty (`lost_point`) on the matrix drawn in
//!   *test* mode — format and version information and the dark module all light — and keeps the
//!   first lowest.

use base64::Engine as _;
use qrcode::bits::Bits;
use qrcode::canvas::{Canvas, MaskPattern};
use qrcode::types::{Color, EcLevel, Version};

/// The payload does not fit a version-40 code at level M.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataOverflow;

impl std::fmt::Display for DataOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the data does not fit a QR code")
    }
}

impl std::error::Error for DataOverflow {}

const ALPHANUMERIC: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const MINIMUM: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Numeric,
    Alphanumeric,
    Byte,
}

/// Where the first match of the split pattern lies in `data`: a whole maximal run of at least
/// [`MINIMUM`] class characters; for a short payload, `^class+$` (where `$` also matches before a
/// final newline).
fn find(data: &[u8], class: fn(u8) -> bool, short: bool) -> Option<(usize, usize)> {
    if short {
        let body = data.strip_suffix(b"\n").filter(|_| !data.iter().all(|b| class(*b))).unwrap_or(data);
        return (!body.is_empty() && body.iter().all(|b| class(*b))).then_some((0, body.len()));
    }
    let mut start = 0;
    while start < data.len() {
        if !class(data[start]) {
            start += 1;
            continue;
        }
        let end = data[start..].iter().position(|b| !class(*b)).map_or(data.len(), |offset| start + offset);
        if end - start >= MINIMUM {
            return Some((start, end));
        }
        start = end;
    }
    None
}

/// `_optimal_split(data, pattern)`: `(matched, chunk)` pieces, in order.
fn split(data: &[u8], class: fn(u8) -> bool, short: bool) -> Vec<(bool, &[u8])> {
    let (mut pieces, mut rest) = (Vec::new(), data);
    while !rest.is_empty() {
        let Some((start, end)) = find(rest, class, short) else { break };
        if start > 0 {
            pieces.push((false, &rest[..start]));
        }
        pieces.push((true, &rest[start..end]));
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        pieces.push((false, rest));
    }
    pieces
}

/// `optimal_data_chunks(data, minimum=20)`.
fn segments(data: &[u8]) -> Vec<(Mode, &[u8])> {
    let short = data.len() <= MINIMUM;
    let mut out = Vec::new();
    for (numeric, chunk) in split(data, |b| b.is_ascii_digit(), short) {
        if numeric {
            out.push((Mode::Numeric, chunk));
            continue;
        }
        for (alphanumeric, piece) in split(chunk, |b| ALPHANUMERIC.contains(&b), short) {
            out.push((if alphanumeric { Mode::Alphanumeric } else { Mode::Byte }, piece));
        }
    }
    out
}

/// The character-count bits of a mode at a version (python-qrcode's three size classes).
fn length_bits(mode: Mode, version: i16) -> usize {
    let class = if version < 10 {
        0
    } else if version < 27 {
        1
    } else {
        2
    };
    match mode {
        Mode::Numeric => [10, 12, 14][class],
        Mode::Alphanumeric => [9, 11, 13][class],
        Mode::Byte => [8, 16, 16][class],
    }
}

fn data_bits(mode: Mode, length: usize) -> usize {
    match mode {
        Mode::Numeric => length / 3 * 10 + [0, 4, 7][length % 3],
        Mode::Alphanumeric => length / 2 * 11 + (length % 2) * 6,
        Mode::Byte => length * 8,
    }
}

fn capacity(version: i16) -> usize {
    Bits::new(Version::Normal(version)).max_len(EcLevel::M).expect("versions 1..=40 have an M capacity")
}

fn size_class(version: i16) -> u8 {
    if version < 10 {
        0
    } else if version < 27 {
        1
    } else {
        2
    }
}

/// `best_fit(start)`: the smallest version from `start` whose capacity holds the bits, computed
/// with the length fields of `start`'s size class and redone when the class changed.
fn best_fit(segments: &[(Mode, &[u8])], start: i16) -> Result<i16, DataOverflow> {
    let needed: usize =
        segments.iter().map(|(mode, data)| 4 + length_bits(*mode, start) + data_bits(*mode, data.len())).sum();
    let version = (start..=40).find(|version| capacity(*version) >= needed).ok_or(DataOverflow)?;
    if size_class(version) != size_class(start) {
        return best_fit(segments, version);
    }
    Ok(version)
}

const MASKS: [MaskPattern; 8] = [
    MaskPattern::Checkerboard,
    MaskPattern::HorizontalLines,
    MaskPattern::VerticalLines,
    MaskPattern::DiagonalLines,
    MaskPattern::LargeCheckerboard,
    MaskPattern::Fields,
    MaskPattern::Diamonds,
    MaskPattern::Meadow,
];

/// The modules as rows of booleans (`modules[row][col]`, dark = true).
fn rows(canvas: Canvas, width: usize) -> Vec<Vec<bool>> {
    canvas.into_colors().chunks(width).map(|row| row.iter().map(|color| *color == Color::Dark).collect()).collect()
}

/// python-qrcode's `makeImpl(test=True, …)` differs from the final matrix only where it leaves
/// the format information, the dark module and the version information light.
fn clear_information(modules: &mut [Vec<bool>], version: i16) {
    let n = modules.len();
    for i in 0..15 {
        let row = if i < 6 {
            i
        } else if i < 8 {
            i + 1
        } else {
            n - 15 + i
        };
        modules[row][8] = false;
        let col = if i < 8 {
            n - i - 1
        } else if i < 9 {
            7
        } else {
            14 - i
        };
        modules[8][col] = false;
    }
    modules[n - 8][8] = false;
    if version >= 7 {
        for i in 0..18 {
            modules[i / 3][i % 3 + n - 11] = false;
            modules[i % 3 + n - 11][i / 3] = false;
        }
    }
}

/// `util.lost_point(modules)`, including its shortcuts (they change which runs are scored).
// Columns are walked by index, as python-qrcode does: an iterator over rows would hide the shape.
#[allow(clippy::needless_range_loop)]
fn lost_point(modules: &[Vec<bool>]) -> u64 {
    let n = modules.len();
    let mut lost = 0u64;

    // Level 1: runs of five or more of one colour, in rows and columns.
    let mut container = vec![0u64; n + 1];
    let mut runs = |line: &mut dyn Iterator<Item = bool>| {
        let mut previous = None;
        let mut length = 0usize;
        for color in line {
            if Some(color) == previous {
                length += 1;
            } else {
                if length >= 5 {
                    container[length] += 1;
                }
                length = 1;
                previous = Some(color);
            }
        }
        if length >= 5 {
            container[length] += 1;
        }
    };
    for row in modules {
        runs(&mut row.iter().copied());
    }
    for col in 0..n {
        runs(&mut (0..n).map(|row| modules[row][col]));
    }
    lost += (5..=n).map(|length| container[length] * (length as u64 - 2)).sum::<u64>();

    // Level 2: 2×2 blocks of one colour (a mismatch on the right skips the next column).
    for row in 0..n - 1 {
        let (this, next) = (&modules[row], &modules[row + 1]);
        let mut col = 0;
        while col < n - 1 {
            let top_right = this[col + 1];
            if top_right != next[col + 1] {
                col += 2;
                continue;
            }
            if top_right == this[col] && top_right == next[col] {
                lost += 3;
            }
            col += 1;
        }
    }

    // Level 3: 1:1:3:1:1 finder-like patterns with four light modules on one side.
    if n > 10 {
        let finder = |get: &dyn Fn(usize) -> bool, at: usize| {
            !get(at + 1)
                && get(at + 4)
                && !get(at + 5)
                && get(at + 6)
                && !get(at + 9)
                && ((get(at) && get(at + 2) && get(at + 3) && !get(at + 7) && !get(at + 8) && !get(at + 10))
                    || (!get(at) && !get(at + 2) && !get(at + 3) && get(at + 7) && get(at + 8) && get(at + 10)))
        };
        let mut scan = |get: &dyn Fn(usize) -> bool| {
            let mut at = 0;
            while at < n - 10 {
                if finder(get, at) {
                    lost += 40;
                }
                at += if get(at + 10) { 2 } else { 1 };
            }
        };
        for row in modules {
            scan(&|col| row[col]);
        }
        for col in 0..n {
            scan(&|row| modules[row][col]);
        }
    }

    // Level 4: every 5 % of dark modules away from 50 %.
    let dark = modules.iter().flatten().filter(|dark| **dark).count();
    let percent = dark as f64 / (n * n) as f64;
    lost += ((percent * 100.0 - 50.0).abs() / 5.0) as u64 * 10;
    lost
}

/// The module matrix python-qrcode draws for `data` (UTF-8 bytes), without the quiet zone.
pub fn matrix(data: &[u8]) -> Result<Vec<Vec<bool>>, DataOverflow> {
    let segments = segments(data);
    let version = best_fit(&segments, 1)?;
    let mut bits = Bits::new(Version::Normal(version));
    for (mode, piece) in &segments {
        let pushed = match mode {
            Mode::Numeric => bits.push_numeric_data(piece),
            Mode::Alphanumeric => bits.push_alphanumeric_data(piece),
            Mode::Byte => bits.push_byte_data(piece),
        };
        pushed.map_err(|_| DataOverflow)?;
    }
    bits.push_terminator(EcLevel::M).map_err(|_| DataOverflow)?;
    let (data, ec) = qrcode::ec::construct_codewords(&bits.into_bytes(), Version::Normal(version), EcLevel::M)
        .map_err(|_| DataOverflow)?;
    let mut canvas = Canvas::new(Version::Normal(version), EcLevel::M);
    canvas.draw_all_functional_patterns();
    canvas.draw_data(&data, &ec);
    let width = Version::Normal(version).width() as usize;
    let mut best: Option<(u64, MaskPattern)> = None;
    for mask in MASKS {
        let mut candidate = canvas.clone();
        candidate.apply_mask(mask);
        let mut modules = rows(candidate, width);
        clear_information(&mut modules, version);
        let lost = lost_point(&modules);
        if best.is_none_or(|(lowest, _)| lost < lowest) {
            best = Some((lost, mask));
        }
    }
    let (_, mask) = best.expect("eight masks were scored");
    canvas.apply_mask(mask);
    Ok(rows(canvas, width))
}

/// The standalone SVG python-qrcode's `SvgPathImage` writes (box size 10, border 4): an XML
/// declaration, then one `<svg>` with one `<path>` of a square per dark module, in millimetres.
pub fn svg(modules: &[Vec<bool>]) -> String {
    let size = modules.len() + 8;
    let mut path = String::new();
    for (row, line) in modules.iter().enumerate() {
        for (col, dark) in line.iter().enumerate() {
            if *dark {
                let (x, y) = (col + 4, row + 4);
                path.push_str(&format!("M{x},{y}H{}V{}H{x}z", x + 1, y + 1));
            }
        }
    }
    format!(
        "<?xml version='1.0' encoding='UTF-8'?>\n<svg width=\"{size}mm\" height=\"{size}mm\" version=\"1.1\" \
         viewBox=\"0 0 {size} {size}\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"{path}\" id=\"qr-path\" \
         fill=\"#000000\" fill-opacity=\"1\" fill-rule=\"nonzero\" stroke=\"none\" /></svg>"
    )
}

/// `data:image/svg+xml;base64,` + the SVG of the QR code of `text`.
pub fn data_uri(text: &str) -> Result<String, DataOverflow> {
    let svg = svg(&matrix(text.as_bytes())?);
    Ok(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmentation_follows_optimal_data_chunks() {
        let modes =
            |data: &[u8]| segments(data).into_iter().map(|(mode, piece)| (mode, piece.to_vec())).collect::<Vec<_>>();
        assert_eq!(modes(b"12345"), vec![(Mode::Numeric, b"12345".to_vec())]);
        assert_eq!(modes(b"123\n"), vec![(Mode::Numeric, b"123".to_vec()), (Mode::Byte, b"\n".to_vec())]);
        assert_eq!(modes(b"ABC"), vec![(Mode::Alphanumeric, b"ABC".to_vec())]);
        assert_eq!(modes(b"abc"), vec![(Mode::Byte, b"abc".to_vec())]);
        let long = [&b"x"[..], &b"1".repeat(20), b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"y"].concat();
        assert_eq!(
            modes(&long),
            vec![
                (Mode::Byte, b"x".to_vec()),
                (Mode::Numeric, b"1".repeat(20)),
                (Mode::Alphanumeric, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec()),
                (Mode::Byte, b"y".to_vec()),
            ]
        );
    }

    #[test]
    fn an_oversized_payload_overflows() {
        assert_eq!(data_uri(&"y".repeat(2332)), Err(DataOverflow));
        assert!(data_uri(&"y".repeat(2331)).is_ok());
    }
}
