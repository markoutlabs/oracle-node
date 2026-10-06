//! Book levels from the text venues send.

use oracle_types::{Fixed, Level};

use crate::DecodeError;

/// Parses one level from the strings a venue sends.
pub(crate) fn level(price: &str, qty: &str) -> Result<Level, DecodeError> {
    let parse = |field: &'static str, value: &str| {
        value.parse::<Fixed>().map_err(|_| DecodeError::BadDecimal {
            field,
            value: value.to_owned(),
        })
    };
    Ok(Level {
        price: parse("depth price", price)?,
        qty: parse("depth size", qty)?,
    })
}
