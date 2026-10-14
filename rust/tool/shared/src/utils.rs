use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::iter::repeat_with;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// The number of random alphanumeric characters in the tempfiles.
const TEMPFILE_RANDOM_LENGTH: usize = 32;

/// Extension for a temporary directory that enables creating secure temporary files in it.
pub trait SecureTempDirExt {
    fn create_secure_file(&self, path: &Path) -> Result<fs::File>;
    fn write_secure_file(&self, contents: impl AsRef<[u8]>) -> Result<PathBuf>;
}

/// This implementation has three useful properties:
///
/// - Files are created with mode 0o600, so that they are only accessible by the current user.
/// - Files are named and not ephemeral (unlike a real temporary file).
/// - The directory and its children are cleaned up (i.e. deleted) when the variable that holds the
///   directory goes out of scope.
///
/// This protects against an attacker _without_ root access from modifying files undetected. It
/// provides no prection against an attacker _with_ root access. Additionally, because the files
/// have named paths, they can be passed to external programs while still being securely deleted
/// after they are not needed anymore.
impl SecureTempDirExt for TempDir {
    /// Create a temporary file that can only be accessed by the current Linux user.
    fn create_secure_file(&self, path: &Path) -> Result<fs::File> {
        fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create tempfile: {path:?}"))
    }

    /// Create a temporary file and write a `u8` slice to it.
    fn write_secure_file(&self, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
        let path = self.path().join(tmpname());
        let mut tmpfile = self.create_secure_file(&path)?;

        tmpfile
            .write_all(contents.as_ref())
            .with_context(|| format!("Failed to write to tempfile {path:?}"))?;

        Ok(path)
    }
}

/// Generate a random (but not cryptographically secure) name for a temporary file.
///
/// This is heavily inspired by the way temporary names are generated in the `tempfile` crate.
/// Since the `tempfile` crate does not expose this functionality, we have to recreate it here.
pub fn tmpname() -> OsString {
    let mut buf = OsString::with_capacity(TEMPFILE_RANDOM_LENGTH);
    let mut char_buf = [0u8; 4];
    for c in repeat_with(fastrand::alphanumeric).take(TEMPFILE_RANDOM_LENGTH) {
        buf.push(c.encode_utf8(&mut char_buf));
    }
    buf
}

type Hash = sha2::digest::Output<Sha256>;

/// Compute the SHA 256 hash of a file.
pub fn file_hash(file: &Path) -> Result<Hash> {
    let mut input =
        fs::File::open(file).with_context(|| format!("Failed to read file to hash: {file:?}"))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to read file to hash: {file:?}"));
            }
        };
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_empty_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            file_hash(file.path())
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hashes_known_content() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"abc").unwrap();
        assert_eq!(
            file_hash(file.path())
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hashes_content_across_multiple_buffers_and_partial_tail() {
        let content: Vec<u8> = (0..3 * 64 * 1024 + 17).map(|i| (i % 251) as u8).collect();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&content).unwrap();
        assert_eq!(file_hash(file.path()).unwrap(), Sha256::digest(&content));
    }

    #[test]
    fn retains_context_for_open_and_read_failures() {
        let directory = tempfile::tempdir().unwrap();
        for path in [
            directory.path().join("missing"),
            directory.path().to_path_buf(),
        ] {
            let error = file_hash(&path).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("Failed to read file to hash: {path:?}")
            );
            assert!(error.source().is_some());
        }
    }
}
