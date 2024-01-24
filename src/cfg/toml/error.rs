use std::fmt::{self, Debug, Display};

/// Error that can occur when deserializing TOML.
#[derive(Debug)]
pub(super) struct Error {
    pub(super) kind: ErrorKind,
    pub(super) line: Option<usize>,
    pub(super) col: usize,
    pub(super) at: Option<usize>,
    pub(super) message: String,
    pub(super) key: Vec<String>,
}

impl std::error::Error for Error {}

/// Errors that can occur when deserializing a type.
#[derive(Debug)]
pub(super) enum ErrorKind {
    /// EOF was reached when looking for a value.
    UnexpectedEof,

    /// An invalid character not allowed in a string was found.
    InvalidCharInString(char),

    /// An invalid character was found as an escape.
    InvalidEscape(char),

    /// An invalid character was found in a hex escape.
    InvalidHexEscape(char),

    /// An invalid escape value was specified in a hex escape in a string.
    ///
    /// Valid values are in the plane of unicode codepoints.
    InvalidEscapeValue(u32),

    /// A newline in a string was encountered when one was not allowed.
    NewlineInString,

    /// An unexpected character was encountered, typically when looking for a
    /// value.
    Unexpected(char),

    /// An unterminated string was found where EOF was found before the ending
    /// EOF mark.
    UnterminatedString,

    /// A newline was found in a table key.
    NewlineInTableKey,

    /// A number failed to parse.
    NumberInvalid,

    /// Wanted one sort of token, but found another.
    Wanted {
        /// Expected token type.
        expected: &'static str,
        /// Actually found token type.
        found: &'static str,
    },

    /// A duplicate table definition was found.
    DuplicateTable(String),

    /// Duplicate key in table.
    DuplicateKey(String),

    /// A previously defined table was redefined as an array.
    RedefineAsArray,

    /// Multiline strings are not allowed for key.
    MultilineStringKey,

    /// A custom error which could be generated when deserializing a particular
    /// type.
    Custom,

    /// A tuple with a certain number of elements was expected but something
    /// else was found.
    ExpectedTuple(usize),

    /// Expected table keys to be in increasing tuple index order, but something
    /// else was found.
    ExpectedTupleIndex {
        /// Expected index.
        expected: usize,
        /// Key that was specified.
        found: String,
    },

    /// An empty table was expected but entries were found.
    ExpectedEmptyTable,

    /// Dotted key attempted to extend something that is not a table.
    DottedKeyInvalidType,

    /// An unexpected key was encountered.
    ///
    /// Used when deserializing a struct with a limited set of fields.
    UnexpectedKeys {
        /// The unexpected keys.
        keys: Vec<String>,
        /// Keys that may be specified.
        available: &'static [&'static str],
    },

    /// Unquoted string was found when quoted one was expected.
    UnquotedString,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::UnexpectedEof => f.write_str("unexpected eof encountered")?,
            ErrorKind::InvalidCharInString(c) => write!(
                f,
                "invalid character in string: `{}`",
                c.escape_default().collect::<String>()
            )?,
            ErrorKind::InvalidEscape(c) => write!(
                f,
                "invalid escape character in string: `{}`",
                c.escape_default().collect::<String>()
            )?,
            ErrorKind::InvalidHexEscape(c) => write!(
                f,
                "invalid hex escape character in string: `{}`",
                c.escape_default().collect::<String>()
            )?,
            ErrorKind::InvalidEscapeValue(c) => write!(f, "invalid escape value: `{}`", c)?,
            ErrorKind::NewlineInString => f.write_str("newline in string found")?,
            ErrorKind::Unexpected(ch) => write!(
                f,
                "unexpected character found: `{}`",
                ch.escape_default().collect::<String>()
            )?,
            ErrorKind::UnterminatedString => f.write_str("unterminated string")?,
            ErrorKind::NewlineInTableKey => f.write_str("found newline in table key")?,
            ErrorKind::Wanted { expected, found } => {
                write!(f, "expected {}, found {}", expected, found)?;
            }
            ErrorKind::NumberInvalid => f.write_str("invalid number")?,
            ErrorKind::DuplicateTable(ref s) => {
                write!(f, "redefinition of table `{}`", s)?;
            }
            ErrorKind::DuplicateKey(ref s) => {
                write!(f, "duplicate key: `{}`", s)?;
            }
            ErrorKind::RedefineAsArray => f.write_str("table redefined as array")?,
            ErrorKind::MultilineStringKey => {
                f.write_str("multiline strings are not allowed for key")?
            }
            ErrorKind::Custom => f.write_str(&self.message)?,
            ErrorKind::ExpectedTuple(l) => write!(f, "expected table with length {}", l)?,
            ErrorKind::ExpectedTupleIndex {
                expected,
                ref found,
            } => write!(f, "expected table key `{}`, but was `{}`", expected, found)?,
            ErrorKind::ExpectedEmptyTable => f.write_str("expected empty table")?,
            ErrorKind::DottedKeyInvalidType => {
                f.write_str("dotted key attempted to extend non-table type")?;
            }
            ErrorKind::UnexpectedKeys {
                ref keys,
                available,
            } => write!(
                f,
                "unexpected keys in table: `{:?}`, available keys: `{:?}`",
                keys, available
            )?,
            ErrorKind::UnquotedString => write!(
                f,
                "invalid TOML value, did you mean to use a quoted string?"
            )?,
        }

        if !self.key.is_empty() {
            write!(f, " for key `")?;
            for (i, k) in self.key.iter().enumerate() {
                if i > 0 {
                    write!(f, ".")?;
                }
                write!(f, "{}", k)?;
            }
            write!(f, "`")?;
        }

        if let Some(line) = self.line {
            write!(f, " at line {} column {}", line + 1, self.col + 1)?;
        }

        Ok(())
    }
}
