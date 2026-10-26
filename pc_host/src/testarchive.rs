//! Byte-level tar and zip writers for the tests: they must be able to write what no well-behaved
//! library writes (absolute and `..` names, backslashes, devices, payloads on directories,
//! lying sizes), as the Python tests did with `tarfile.TarInfo` and `zipfile.ZipInfo`.

use std::io::Write;

/// One tar member, Python `TarInfo` style (`type`, `mode`, `linkname`, data, an explicit size).
#[derive(Clone, Debug)]
pub struct TarSpec {
    pub name: String,
    pub kind: u8,
    pub mode: u32,
    pub linkname: String,
    pub data: Vec<u8>,
    /// The size field when it should differ from `data.len()`.
    pub size: Option<u64>,
}

impl TarSpec {
    pub fn file(name: &str, data: &[u8]) -> Self {
        TarSpec { name: name.into(), kind: b'0', mode: 0o644, linkname: String::new(), data: data.to_vec(), size: None }
    }

    pub fn dir(name: &str) -> Self {
        TarSpec { name: name.into(), kind: b'5', mode: 0o755, linkname: String::new(), data: Vec::new(), size: None }
    }

    pub fn symlink(name: &str, target: &str) -> Self {
        TarSpec { name: name.into(), kind: b'2', mode: 0o777, linkname: target.into(), data: Vec::new(), size: None }
    }

    pub fn with_kind(mut self, kind: u8) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_link(mut self, target: &str) -> Self {
        self.linkname = target.into();
        self
    }
}

fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}");
    field[..width].copy_from_slice(&text.as_bytes()[text.len() - width..]);
    field[width] = 0;
}

fn header(name: &[u8], kind: u8, mode: u32, size: u64, linkname: &[u8]) -> [u8; 512] {
    let mut block = [0u8; 512];
    let name = &name[..name.len().min(100)];
    block[..name.len()].copy_from_slice(name);
    octal(&mut block[100..108], mode as u64);
    octal(&mut block[108..116], 43210);
    octal(&mut block[116..124], 43210);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], 0);
    block[156] = kind;
    let link = &linkname[..linkname.len().min(100)];
    block[157..157 + link.len()].copy_from_slice(link);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|b| *b as u32).sum();
    let text = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(text.as_bytes());
    block
}

fn pad(out: &mut Vec<u8>) {
    let rest = out.len() % 512;
    if rest != 0 {
        out.extend(std::iter::repeat_n(0u8, 512 - rest));
    }
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut length = body.len() + 1;
    loop {
        let candidate = format!("{length}{body}");
        if candidate.len() == length {
            return candidate.into_bytes();
        }
        length = candidate.len();
    }
}

/// A plain (uncompressed) tar; names over 100 bytes get a pax `x` header, as Python's default
/// `PAX_FORMAT` writes them.
pub fn tar_bytes(members: &[TarSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    for member in members {
        let mut records = Vec::new();
        if member.name.len() > 100 {
            records.extend(pax_record("path", &member.name));
        }
        if member.linkname.len() > 100 {
            records.extend(pax_record("linkpath", &member.linkname));
        }
        if !records.is_empty() {
            out.extend_from_slice(&header(b"././@PaxHeader", b'x', 0o644, records.len() as u64, b""));
            out.extend_from_slice(&records);
            pad(&mut out);
        }
        let size = member.size.unwrap_or(member.data.len() as u64);
        out.extend_from_slice(&header(
            member.name.as_bytes(),
            member.kind,
            member.mode,
            size,
            member.linkname.as_bytes(),
        ));
        out.extend_from_slice(&member.data);
        pad(&mut out);
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// `tar.gz` of `members`.
pub fn tar_gz(members: &[TarSpec]) -> Vec<u8> {
    gzip(&tar_bytes(members))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// One stored zip member; `external_mode` lands in the high 16 bits of the external attributes.
pub struct ZipSpec {
    pub name: String,
    pub data: Vec<u8>,
    pub external_mode: u32,
}

impl ZipSpec {
    pub fn file(name: &str, data: &[u8]) -> Self {
        ZipSpec { name: name.into(), data: data.to_vec(), external_mode: 0o100644 }
    }
}

/// A stored (uncompressed) zip, `zipfile.ZipFile(..., "w").writestr` style. Returns the bytes
/// and the offset of each member's central directory header.
pub fn zip_bytes(members: &[ZipSpec]) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut central_offsets = Vec::new();
    let mut records = Vec::new();
    for member in members {
        let offset = out.len() as u32;
        let crc = crc32(&member.data);
        let size = member.data.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x21u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(member.name.as_bytes());
        out.extend_from_slice(&member.data);
        records.push((offset, crc, size));
    }
    let central_start = out.len() as u32;
    for (member, (offset, crc, size)) in members.iter().zip(records) {
        central_offsets.push(out.len() + central.len());
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&(0x0300u16 | 20).to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0x21u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&(member.external_mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(member.name.as_bytes());
    }
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    (out, central_offsets)
}
