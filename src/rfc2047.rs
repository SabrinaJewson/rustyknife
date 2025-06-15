//! [Header extensions for non-ASCII text]
//!
//! [Header extensions for non-ASCII text]: https://tools.ietf.org/html/rfc2047

use crate::rfc3461::hexpair;
use crate::util::*;
use base64::Engine as _;
use encoding_rs::{Encoding, UTF_8}; // TODO: was ASCII
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_while1;
use nom::combinator::all_consuming;
use nom::combinator::map;
use nom::combinator::opt;
use nom::multi::many0;
use nom::sequence::delimited;
use nom::sequence::preceded;
use nom::sequence::terminated;
use nom::sequence::tuple;
use std::borrow::Cow;

fn token(input: &[u8]) -> NomResult<'_, &[u8]> {
    take_while1(|c: u8| c.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?.=".contains(&c))(input)
}

fn encoded_text(input: &[u8]) -> NomResult<'_, &[u8]> {
    take_while1(|c: u8| c.is_ascii_graphic() && c != b'?')(input)
}

fn _qp_encoded_text(input: &[u8]) -> NomResult<'_, Vec<u8>> {
    many0(alt((
        preceded(tag("="), hexpair),
        map(tag("_"), |_| b' '),
        take1_filter(|_| true),
    )))(input)
}

// Decode the modified quoted-printable as defined by this RFC.
fn decode_qp(input: &[u8]) -> Option<Vec<u8>> {
    all_consuming(_qp_encoded_text)(input).ok().map(|(_, o)| o)
}

// Undoes the quoted-printable or base64 encoding.
fn decode_text(encoding: &[u8], text: &[u8]) -> Option<Vec<u8>> {
    match encoding {
        [b'q' | b'Q'] => decode_qp(text),
        [b'b' | b'B'] => base64::engine::general_purpose::STANDARD.decode(text).ok(),
        _ => None,
    }
}

/// Decode an encoded word.
///
/// # Examples
/// ```
/// use rustyknife::rfc2047::encoded_word;
///
/// let (_, decoded) = encoded_word(b"=?x-sjis?B?lEWWQI7Kg4GM9ZTygs6CtSiPzik=?=").unwrap();
/// assert_eq!(decoded.decode(), "忍法写メ光飛ばし(笑)");
/// ```
pub fn encoded_word(input: &[u8]) -> NomResult<'_, EncodedWord<'_>> {
    map(
        tuple((
            preceded(tag("=?"), token),
            opt(preceded(tag("*"), token)),
            delimited(tag("?"), token, tag("?")),
            terminated(encoded_text, tag("?=")),
        )),
        |(charset, _lang, encoding, text)| EncodedWord {
            charset: charset::decode_ascii(charset),
            bytes: decode_text(encoding, text).unwrap_or_else(|| text.to_vec()),
        },
    )(input)
}

/// An encoded word. Constructed by [`encoded_word`].
#[derive(Debug)]
pub struct EncodedWord<'a> {
    charset: Cow<'a, str>,
    bytes: Vec<u8>,
}

impl EncodedWord<'_> {
    pub fn decode(&self) -> Cow<'_, str> {
        Encoding::for_label(self.charset.as_bytes())
            .unwrap_or(UTF_8)
            .decode_without_bom_handling(&self.bytes)
            .0
    }
}
