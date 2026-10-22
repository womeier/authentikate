//! Immutable records published by hard link within the `/accounts` preopen.
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use exports::authentikate::storage::accounts::{Error, Guest};
use sha2::{Digest, Sha256};
use wasi::filesystem::types::{Descriptor, DescriptorFlags, ErrorCode, OpenFlags, PathFlags};

const MAGIC: &[u8; 8] = b"AKSTORE1";
// The HTTP request is at most 16 KiB; leave ample room for the encoded record.
const MAX_RECORD: usize = 1024 * 1024;

struct Component;
fn io_error(_: ErrorCode) -> Error {
    Error::Unavailable
}
fn directory() -> Result<Descriptor, Error> {
    wasi::filesystem::preopens::get_directories()
        .into_iter()
        .find_map(|(fd, name)| (name == "/accounts").then_some(fd))
        .ok_or(Error::Unavailable)
}
fn filename(key: &str) -> String {
    format!("{:x}.account", Sha256::digest(key.as_bytes()))
}

fn encode(key: &str, value: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() > MAX_RECORD - 12 || value.len() > MAX_RECORD - 12 - key.len() {
        return Err(Error::Unavailable);
    }
    let mut bytes = Vec::with_capacity(12 + key.len() + value.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(value);
    Ok(bytes)
}
fn decode(key: &str, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() < 12 || bytes.len() > MAX_RECORD || &bytes[..8] != MAGIC {
        return Err(Error::Unavailable);
    }
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if length > bytes.len() - 12
        || length != key.len()
        || bytes.get(12..12 + length) != Some(key.as_bytes())
    {
        return Err(Error::Unavailable);
    }
    Ok(bytes[12 + length..].to_vec())
}
fn get(dir: &Descriptor, key: &str) -> Result<Option<Vec<u8>>, Error> {
    let file = match dir.open_at(
        PathFlags::empty(),
        &filename(key),
        OpenFlags::empty(),
        DescriptorFlags::READ,
    ) {
        Ok(file) => file,
        Err(ErrorCode::NoEntry) => return Ok(None),
        Err(code) => return Err(io_error(code)),
    };
    let mut bytes = Vec::new();
    loop {
        let (chunk, eof) = file.read(4096, bytes.len() as u64).map_err(io_error)?;
        if bytes.len() + chunk.len() > MAX_RECORD {
            return Err(Error::Unavailable);
        }
        if chunk.is_empty() && !eof {
            return Err(Error::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
        if eof {
            break;
        }
    }
    decode(key, &bytes).map(Some)
}

fn create(dir: &Descriptor, key: &str, value: &[u8]) -> Result<bool, Error> {
    let bytes = encode(key, value)?;
    let mut temporary = String::new();
    let mut opened = None;
    for _ in 0..8 {
        let random = wasi::random::random::get_random_bytes(32);
        temporary = format!(".tmp-{:x}", Sha256::digest(random));
        match dir.open_at(
            PathFlags::empty(),
            &temporary,
            OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
            DescriptorFlags::WRITE,
        ) {
            Ok(file) => {
                opened = Some(file);
                break;
            }
            Err(ErrorCode::Exist) => continue,
            Err(code) => return Err(io_error(code)),
        }
    }
    let file = opened.ok_or(Error::Unavailable)?;
    let result = (|| {
        let mut offset = 0;
        while offset < bytes.len() {
            let count = file
                .write(
                    &bytes[offset..bytes.len().min(offset + 4096)],
                    offset as u64,
                )
                .map_err(io_error)? as usize;
            if count == 0 {
                return Err(Error::Unavailable);
            }
            offset += count;
        }
        file.sync().map_err(io_error)?;
        // This is the sole publication point: complete contents and name appear together.
        match dir.link_at(PathFlags::empty(), &temporary, dir, &filename(key)) {
            Ok(()) => {
                // A sync failure after publication is an uncertain durability outcome,
                // not permission to remove or overwrite the now-visible account.
                dir.sync().map_err(io_error)?;
                Ok(true)
            }
            Err(ErrorCode::Exist) => Ok(false),
            Err(code) => Err(io_error(code)),
        }
    })();
    drop(file);
    // Cleanup failure cannot undo publication. Crashed instances may leave these too.
    let _ = dir.unlink_file_at(&temporary);
    result
}

impl Guest for Component {
    fn get(key: String) -> Result<Option<Vec<u8>>, Error> {
        get(&directory()?, &key)
    }
    fn create(key: String, value: Vec<u8>) -> Result<bool, Error> {
        create(&directory()?, &key, &value)
    }
}
export!(Component);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_preserves_exact_keys_and_values() {
        for key in [
            "../a/b@example.test",
            "A@example.test",
            "a@example.test",
            "",
            &"x".repeat(20_000),
        ] {
            let bytes = encode(key, b"\0arbitrary value\xff").unwrap();
            assert_eq!(decode(key, &bytes).unwrap(), b"\0arbitrary value\xff");
            assert!(decode(&format!("{key}x"), &bytes).is_err());
            let name = filename(key);
            assert_eq!(name.len(), 72);
            assert!(name[..64].bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert_ne!(filename("A@example.test"), filename("a@example.test"));
    }
    #[test]
    fn malformed_and_oversized_envelopes_are_errors() {
        for bytes in [
            vec![],
            vec![0; 12],
            [MAGIC.as_slice(), &u32::MAX.to_le_bytes()].concat(),
        ] {
            assert!(decode("a", &bytes).is_err());
        }
        assert!(encode("a", &vec![0; MAX_RECORD]).is_err());
        assert!(encode(&"a".repeat(MAX_RECORD), b"").is_err());
    }
}
