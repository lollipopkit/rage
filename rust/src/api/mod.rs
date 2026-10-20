//! age encryption (<https://age-encryption.org/v1>) through the `age` crate.
//!
//! Every function here takes and returns whole values or file paths, so the C
//! ABI (`crate::ffi`) never hands Dart a Rust object to dispose.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::iter;
use std::path::{Path, PathBuf};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret, SecretString};
use age::{DecryptError, EncryptError, Identity, Recipient, scrypt, x25519};

/// The highest scrypt work factor (`log2(N)`) accepted when encrypting.
///
/// age's own decryptors refuse a factor more than four above what takes about
/// a second on the device reading it, so a much higher one makes a file other
/// devices cannot open.
pub const MAX_ENCRYPT_WORK_FACTOR: u8 = 22;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RageErrorKind {
    /// The passphrase does not open the file.
    WrongPassphrase,
    /// None of the given identities is a recipient of the file.
    NoMatchingKeys,
    /// The file asks for more scrypt work than `max_work_factor` allows.
    ExcessiveWork,
    /// Not an age file, or a header this version does not understand.
    InvalidFormat,
    /// The file was modified or cut short.
    Corrupt,
    /// A recipient or identity string could not be parsed.
    InvalidKey,
    /// An argument outside what is accepted (an empty passphrase, a work factor
    /// out of range, no recipients).
    InvalidArgument,
    /// Reading or writing a file failed.
    Io,
    /// A bug in rage: a Rust panic, caught at the C ABI.
    Internal,
}

/// An error from `rage`.
#[derive(Debug, Clone)]
pub struct RageError {
    pub kind: RageErrorKind,
    pub message: String,
    /// For [`RageErrorKind::ExcessiveWork`]: the work factor the file needs.
    pub required_work_factor: Option<u8>,
}

impl RageError {
    pub(crate) fn new(kind: RageErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            required_work_factor: None,
        }
    }
}

impl std::fmt::Display for RageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for RageError {}

impl From<io::Error> for RageError {
    fn from(e: io::Error) -> Self {
        // The payload is checked chunk by chunk while it is read: a chunk that
        // fails its tag, or a stream that ends before its last chunk, is an
        // `InvalidData` / `UnexpectedEof` read error, not a `DecryptError`.
        let kind = match e.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => RageErrorKind::Corrupt,
            _ => RageErrorKind::Io,
        };
        Self::new(kind, e.to_string())
    }
}

impl From<DecryptError> for RageError {
    fn from(e: DecryptError) -> Self {
        let message = e.to_string();
        match e {
            DecryptError::DecryptionFailed | DecryptError::KeyDecryptionFailed => {
                Self::new(RageErrorKind::WrongPassphrase, message)
            }
            DecryptError::NoMatchingKeys => Self::new(RageErrorKind::NoMatchingKeys, message),
            DecryptError::ExcessiveWork { required, .. } => Self {
                kind: RageErrorKind::ExcessiveWork,
                message,
                required_work_factor: Some(required),
            },
            DecryptError::InvalidHeader | DecryptError::UnknownFormat => {
                Self::new(RageErrorKind::InvalidFormat, message)
            }
            DecryptError::InvalidMac => Self::new(RageErrorKind::Corrupt, message),
            DecryptError::Io(e) => e.into(),
        }
    }
}

impl From<EncryptError> for RageError {
    fn from(e: EncryptError) -> Self {
        match e {
            EncryptError::Io(e) => e.into(),
            e => Self::new(RageErrorKind::InvalidArgument, e.to_string()),
        }
    }
}

/// An X25519 key pair in age's text form.
#[derive(Debug, Clone)]
pub struct X25519KeyPair {
    /// The secret key, `AGE-SECRET-KEY-1…`. Keep it like a password.
    pub identity: String,
    /// The public key, `age1…`, what others encrypt to.
    pub recipient: String,
}

/// Generates a new X25519 key pair.
pub fn generate_x25519() -> X25519KeyPair {
    let identity = x25519::Identity::generate();
    X25519KeyPair {
        recipient: identity.to_public().to_string(),
        identity: identity.to_string().expose_secret().to_owned(),
    }
}

/// The public key (`age1…`) of a secret key (`AGE-SECRET-KEY-1…`).
pub fn x25519_recipient_of(identity: String) -> Result<String, RageError> {
    Ok(parse_identity(&identity)?.to_public().to_string())
}

/// Encrypts `plaintext` with a passphrase (age's scrypt recipient).
///
/// `work_factor` is scrypt's `log2(N)`; `None` picks what takes about a second
/// on this device. `armor` writes the PEM-like text form instead of binary.
pub fn encrypt_with_passphrase(
    plaintext: Vec<u8>,
    passphrase: String,
    work_factor: Option<u8>,
    armor: bool,
) -> Result<Vec<u8>, RageError> {
    let recipient = passphrase_recipient(passphrase, work_factor)?;
    let mut out = Vec::with_capacity(plaintext.len() + 256);
    encrypt_stream(&mut plaintext.as_slice(), &mut out, iter::once(&recipient as &dyn Recipient), armor)?;
    Ok(out)
}

/// Decrypts a passphrase-encrypted file, binary or armored.
///
/// `max_work_factor` bounds the scrypt work a file may ask for (age's default,
/// `None`, is four above what takes a second here); a file asking more fails
/// with [`RageErrorKind::ExcessiveWork`] before any of that work is done.
pub fn decrypt_with_passphrase(
    ciphertext: Vec<u8>,
    passphrase: String,
    max_work_factor: Option<u8>,
) -> Result<Vec<u8>, RageError> {
    let identity = passphrase_identity(passphrase, max_work_factor)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    decrypt_stream(ciphertext.as_slice(), &mut out, iter::once(&identity as &dyn Identity))?;
    Ok(out)
}

/// Encrypts `plaintext` to one or more `age1…` recipients.
pub fn encrypt_to_recipients(
    plaintext: Vec<u8>,
    recipients: Vec<String>,
    armor: bool,
) -> Result<Vec<u8>, RageError> {
    let recipients = parse_recipients(&recipients)?;
    let mut out = Vec::with_capacity(plaintext.len() + 256);
    encrypt_stream(
        &mut plaintext.as_slice(),
        &mut out,
        recipients.iter().map(|r| r as &dyn Recipient),
        armor,
    )?;
    Ok(out)
}

/// Decrypts a file encrypted to recipients with any of `identities`.
pub fn decrypt_with_identities(
    ciphertext: Vec<u8>,
    identities: Vec<String>,
) -> Result<Vec<u8>, RageError> {
    let identities = parse_identities(&identities)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    decrypt_stream(
        ciphertext.as_slice(),
        &mut out,
        identities.iter().map(|i| i as &dyn Identity),
    )?;
    Ok(out)
}

/// [`encrypt_with_passphrase`] from file to file, streaming: memory stays flat
/// whatever the size. `output` is written whole or not at all.
pub fn encrypt_file_with_passphrase(
    input: String,
    output: String,
    passphrase: String,
    work_factor: Option<u8>,
    armor: bool,
) -> Result<(), RageError> {
    let recipient = passphrase_recipient(passphrase, work_factor)?;
    with_files(&input, &output, false, |r, w| {
        encrypt_stream(r, w, iter::once(&recipient as &dyn Recipient), armor)
    })
}

/// [`decrypt_with_passphrase`] from file to file, streaming. `output` is
/// written whole or not at all, owner-only on Unix (it is plaintext).
pub fn decrypt_file_with_passphrase(
    input: String,
    output: String,
    passphrase: String,
    max_work_factor: Option<u8>,
) -> Result<(), RageError> {
    let identity = passphrase_identity(passphrase, max_work_factor)?;
    with_files(&input, &output, true, |r, w| {
        decrypt_stream(r, w, iter::once(&identity as &dyn Identity))
    })
}

/// [`encrypt_to_recipients`] from file to file, streaming.
pub fn encrypt_file_to_recipients(
    input: String,
    output: String,
    recipients: Vec<String>,
    armor: bool,
) -> Result<(), RageError> {
    let recipients = parse_recipients(&recipients)?;
    with_files(&input, &output, false, |r, w| {
        encrypt_stream(r, w, recipients.iter().map(|r| r as &dyn Recipient), armor)
    })
}

/// [`decrypt_with_identities`] from file to file, streaming. Owner-only on Unix.
pub fn decrypt_file_with_identities(
    input: String,
    output: String,
    identities: Vec<String>,
) -> Result<(), RageError> {
    let identities = parse_identities(&identities)?;
    with_files(&input, &output, true, |r, w| {
        decrypt_stream(r, w, identities.iter().map(|i| i as &dyn Identity))
    })
}

fn secret(passphrase: String) -> Result<SecretString, RageError> {
    if passphrase.is_empty() {
        return Err(RageError::new(RageErrorKind::InvalidArgument, "the passphrase is empty"));
    }
    Ok(SecretString::from(passphrase))
}

fn passphrase_recipient(passphrase: String, work_factor: Option<u8>) -> Result<scrypt::Recipient, RageError> {
    let mut recipient = scrypt::Recipient::new(secret(passphrase)?);
    if let Some(log_n) = work_factor {
        if !(1..=MAX_ENCRYPT_WORK_FACTOR).contains(&log_n) {
            return Err(RageError::new(
                RageErrorKind::InvalidArgument,
                format!("work factor {log_n} is outside 1..={MAX_ENCRYPT_WORK_FACTOR}"),
            ));
        }
        recipient.set_work_factor(log_n);
    }
    Ok(recipient)
}

fn passphrase_identity(passphrase: String, max_work_factor: Option<u8>) -> Result<scrypt::Identity, RageError> {
    let mut identity = scrypt::Identity::new(secret(passphrase)?);
    if let Some(max) = max_work_factor {
        identity.set_max_work_factor(max);
    }
    Ok(identity)
}

fn parse_identity(s: &str) -> Result<x25519::Identity, RageError> {
    s.trim()
        .parse::<x25519::Identity>()
        .map_err(|e| RageError::new(RageErrorKind::InvalidKey, e.to_string()))
}

fn parse_identities(identities: &[String]) -> Result<Vec<x25519::Identity>, RageError> {
    if identities.is_empty() {
        return Err(RageError::new(RageErrorKind::InvalidArgument, "no identities"));
    }
    identities.iter().map(|s| parse_identity(s)).collect()
}

fn parse_recipients(recipients: &[String]) -> Result<Vec<x25519::Recipient>, RageError> {
    if recipients.is_empty() {
        return Err(RageError::new(RageErrorKind::InvalidArgument, "no recipients"));
    }
    recipients
        .iter()
        .map(|s| {
            s.trim()
                .parse::<x25519::Recipient>()
                .map_err(|e| RageError::new(RageErrorKind::InvalidKey, e.to_string()))
        })
        .collect()
}

fn encrypt_stream<'a>(
    input: &mut dyn Read,
    output: &mut dyn Write,
    recipients: impl Iterator<Item = &'a dyn Recipient>,
    armor: bool,
) -> Result<(), RageError> {
    let format = if armor { Format::AsciiArmor } else { Format::Binary };
    let armored = ArmoredWriter::wrap_output(output, format)?;
    let mut writer = age::Encryptor::with_recipients(recipients)?.wrap_output(armored)?;
    io::copy(input, &mut writer)?;
    writer.finish()?.finish()?;
    Ok(())
}

fn decrypt_stream<'a>(
    input: impl Read,
    output: &mut dyn Write,
    identities: impl Iterator<Item = &'a dyn Identity>,
) -> Result<(), RageError> {
    // A header that cannot be read is a file that is not age (or not age v1),
    // whatever read error says so; past the header, a bad read is corruption.
    let decryptor = age::Decryptor::new(ArmoredReader::new(input)).map_err(|e| match e {
        DecryptError::Io(e) if matches!(e.kind(), io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof) => {
            RageError::new(RageErrorKind::InvalidFormat, e.to_string())
        }
        e => e.into(),
    })?;
    let mut reader = decryptor.decrypt(identities)?;
    io::copy(&mut reader, output)?;
    Ok(())
}

/// Runs `work` from `input` into a staged copy of `output`, renamed over it
/// only when `work` succeeds, so a failure never leaves half a file or
/// replaces a good one.
fn with_files(
    input: &str,
    output: &str,
    private: bool,
    work: impl FnOnce(&mut dyn Read, &mut dyn Write) -> Result<(), RageError>,
) -> Result<(), RageError> {
    let output = Path::new(output);
    let staged = staged_path(output);
    let result = (|| {
        let mut reader = BufReader::new(File::open(input)?);
        let file = create(&staged, private)?;
        let mut writer = BufWriter::new(file);
        work(&mut reader, &mut writer)?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        fs::rename(&staged, output)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn staged_path(output: &Path) -> PathBuf {
    let name = output.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    output.with_file_name(format!(".{name}.rage-part-{}", std::process::id()))
}

fn create(path: &Path, private: bool) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    options.open(path)
}

