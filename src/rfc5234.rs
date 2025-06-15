use crate::util::*;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::map;

fn sp(input: &[u8]) -> NomResult<'_, &[u8]> {
    tag(" ")(input)
}

fn htab(input: &[u8]) -> NomResult<'_, &[u8]> {
    tag("\t")(input)
}

pub(crate) fn wsp(input: &[u8]) -> NomResult<'_, u8> {
    map(alt((sp, htab)), |x| x[0])(input)
}

pub fn vchar(input: &[u8]) -> NomResult<'_, char> {
    map(take1_filter(|c| c.is_ascii_graphic()), char::from)(input)
}

pub fn crlf(input: &[u8]) -> NomResult<'_, &[u8]> {
    tag("\r\n")(input)
}
