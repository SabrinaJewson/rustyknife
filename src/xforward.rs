//! Postfix [XFORWARD] SMTP extension parser
//!
//! [XFORWARD]: http://www.postfix.org/XFORWARD_README.html

use crate::rfc3461::xtext;
use crate::rfc5234::crlf;
use crate::rfc5234::wsp;
use crate::util::*;
use charset::decode_ascii;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::tag_no_case;
use nom::combinator::map;
use nom::combinator::opt;
use nom::multi::many1;
use nom::multi::separated_list1;
use nom::sequence::delimited;
use nom::sequence::preceded;
use nom::sequence::separated_pair;

/// XFORWARD parameter name and value.
///
/// `"[UNAVAILABLE]"` is represented with a value of `None`.
#[derive(Clone, Debug)]
pub struct Param(pub &'static str, pub Option<String>);

fn command_name(input: &[u8]) -> NomResult<'_, &'static str> {
    alt((
        map(tag_no_case("addr"), |_| "addr"),
        map(tag_no_case("helo"), |_| "helo"),
        map(tag_no_case("ident"), |_| "ident"),
        map(tag_no_case("name"), |_| "name"),
        map(tag_no_case("port"), |_| "port"),
        map(tag_no_case("proto"), |_| "proto"),
        map(tag_no_case("source"), |_| "source"),
    ))(input)
}

fn unavailable(input: &[u8]) -> NomResult<'_, Option<String>> {
    map(tag_no_case("[unavailable]"), |_| None)(input)
}

fn value(input: &[u8]) -> NomResult<'_, Option<String>> {
    alt((unavailable, map(xtext, |x| Some(decode_ascii(&x).into()))))(input)
}

fn param(input: &[u8]) -> NomResult<'_, Param> {
    map(separated_pair(command_name, tag("="), value), |(c, v)| {
        Param(c, v)
    })(input)
}

/// Parse a XFORWARD b`"attr1=value attr2=value"` string.
///
/// Returns a vector of [`Param`].
///
/// The parameter names must be valid and are normalized to
/// lowercase. The values are xtext decoded and a value of
/// `[UNAVAILABLE]` is translated to `None`. No other validation is
/// done.
pub fn xforward_params(input: &[u8]) -> NomResult<'_, Vec<Param>> {
    separated_list1(
        preceded(opt(many1(wsp)), param),
        preceded(many1(wsp), param),
    )(input)
}

pub fn command(input: &[u8]) -> NomResult<'_, Vec<Param>> {
    delimited(tag_no_case("XFORWARD "), xforward_params, crlf)(input)
}
