//! Parsers for [Internet Message Format] messages.
//!
//! Comments are ignored. [RFC 2047] decoding is applied where appropriate.
//!
//! [Internet Message Format]: https://tools.ietf.org/html/rfc5322
//! [RFC 2047]: https://tools.ietf.org/html/rfc2047

use crate::behaviour::*;
use crate::rfc2047::encoded_word;
use crate::rfc2047::EncodedWord;
use crate::rfc5234::*;
use crate::types::*;
use crate::types::{self};
use crate::util::*;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take;
use nom::combinator::map;
use nom::combinator::map_opt;
use nom::combinator::opt;
use nom::combinator::recognize;
use nom::multi::fold_many0;
use nom::multi::many0;
use nom::multi::many1;
use nom::multi::separated_list1;
use nom::sequence::delimited;
use nom::sequence::pair;
use nom::sequence::preceded;
use nom::sequence::separated_pair;
use nom::sequence::terminated;
use std::borrow::Cow;
use std::mem;
use std::str;

#[allow(missing_docs)] // Mostly internal
pub trait Utf8Policy {
    fn vchar(input: &[u8]) -> NomResult<'_, char>;
    fn ctext(input: &[u8]) -> NomResult<'_, char>;
    fn atext(input: &[u8]) -> NomResult<'_, char>;
    fn qtext(input: &[u8]) -> NomResult<'_, char>;
    fn dtext(input: &[u8]) -> NomResult<'_, char>;
}

impl Utf8Policy for Legacy {
    fn vchar(input: &[u8]) -> NomResult<'_, char> {
        crate::rfc5234::vchar(input)
    }

    fn ctext(input: &[u8]) -> NomResult<'_, char> {
        map(
            take1_filter(|c| c.is_ascii_graphic() && c != b'(' && c != b')' && c != b'\\'),
            char::from,
        )(input)
    }

    fn atext(input: &[u8]) -> NomResult<'_, char> {
        map(
            take1_filter(|c| b"!#$%&'*+-/=?^_`{|}~".contains(&c) || c.is_ascii_alphanumeric()),
            char::from,
        )(input)
    }

    fn qtext(input: &[u8]) -> NomResult<'_, char> {
        alt((
            map(
                take1_filter(|c| c.is_ascii_graphic() && c != b'"' && c != b'\\'),
                char::from,
            ),
            _8bit_char,
        ))(input)
    }

    fn dtext(input: &[u8]) -> NomResult<'_, char> {
        map(
            take1_filter(|c| c.is_ascii_graphic() && c != b'[' && c != b'\\' && c != b']'),
            char::from,
        )(input)
    }
}

impl Utf8Policy for Intl {
    fn vchar(input: &[u8]) -> NomResult<'_, char> {
        alt((Legacy::vchar, utf8_non_ascii))(input)
    }

    fn ctext(input: &[u8]) -> NomResult<'_, char> {
        alt((Legacy::ctext, utf8_non_ascii))(input)
    }

    fn atext(input: &[u8]) -> NomResult<'_, char> {
        alt((Legacy::atext, utf8_non_ascii))(input)
    }

    fn qtext(input: &[u8]) -> NomResult<'_, char> {
        alt((
            map(
                take1_filter(|c| c.is_ascii_graphic() && c != b'"' && c != b'\\'),
                char::from,
            ),
            utf8_non_ascii,
            _8bit_char,
        ))(input)
    }

    fn dtext(input: &[u8]) -> NomResult<'_, char> {
        alt((Legacy::dtext, utf8_non_ascii))(input)
    }
}

fn quoted_pair<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, char> {
    preceded(tag("\\"), alt((P::vchar, map(wsp, char::from))))(input)
}

#[derive(Clone, Debug)]
enum CommentContent<'a> {
    Text(Cow<'a, str>),
    Comment(Vec<CommentContent<'a>>),
    QP(char),
}

fn ccontent<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, CommentContent<'_>> {
    alt((
        alt((
            map(recognize_many1(P::ctext), |ct| {
                CommentContent::Text(str::from_utf8(ct).unwrap().into())
            }),
            map(quoted_pair::<P>, CommentContent::QP),
        )),
        map(comment::<P>, CommentContent::Comment),
    ))(input)
}

fn fws(input: &[u8]) -> NomResult<'_, Cow<'_, str>> {
    //CRLF is "semantically invisible"
    map(
        pair(
            opt(terminated(recognize_many0(wsp), crlf)),
            recognize_many1(wsp),
        ),
        |(a, b)| match a {
            Some(a) => {
                let mut out = String::from(str::from_utf8(a).unwrap());
                out.push_str(str::from_utf8(b).unwrap());
                Cow::from(out)
            }
            None => Cow::from(str::from_utf8(b).unwrap()),
        },
    )(input)
}

/// Optional FWS
pub(crate) fn ofws(input: &[u8]) -> NomResult<'_, Cow<'_, str>> {
    map(opt(fws), |i| i.unwrap_or_else(|| Cow::from("")))(input)
}

fn _concat_comment<'a, I: IntoIterator<Item = CommentContent<'a>>>(
    comments: I,
) -> Vec<CommentContent<'a>> {
    let mut out = Vec::new();
    let mut acc_text = String::new();

    let push_text = |bytes: &mut String, out: &mut Vec<CommentContent<'_>>| {
        if !bytes.is_empty() {
            out.push(CommentContent::Text(mem::take(bytes).into()))
        }
    };

    for comment in comments.into_iter() {
        match comment {
            CommentContent::Text(text) => acc_text.push_str(&text),
            CommentContent::QP(qp) => acc_text.push(qp),
            _ => {
                push_text(&mut acc_text, &mut out);
                out.push(comment)
            }
        }
    }
    push_text(&mut acc_text, &mut out);

    out
}

fn comment<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Vec<CommentContent<'_>>> {
    map(
        delimited(
            tag("("),
            pair(
                fold_many0(
                    pair(ofws, ccontent::<P>),
                    Vec::new(),
                    |mut acc, (fws, cc)| {
                        acc.push(CommentContent::Text(fws));
                        acc.push(cc);
                        acc
                    },
                ),
                ofws,
            ),
            tag(")"),
        ),
        |(a, b)| {
            _concat_comment(
                a.into_iter()
                    .chain(std::iter::once(CommentContent::Text(b))),
            )
        },
    )(input)
}

fn cfws<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, &[u8]> {
    alt((
        recognize(pair(many1(pair(ofws, comment::<P>)), ofws)),
        recognize(fws),
    ))(input)
}

#[cfg(feature = "quoted-string-rfc2047")]
fn qcontent<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, QContent<'_>> {
    alt((
        map(encoded_word, QContent::EncodedWord),
        map(recognize_many1(P::qtext), |q| {
            QContent::Literal(String::from_utf8_lossy(q))
        }),
        map(quoted_pair::<P>, QContent::QP),
    ))(input)
}

#[cfg(not(feature = "quoted-string-rfc2047"))]
fn qcontent<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, QContent> {
    alt((
        map(recognize_many1(P::qtext), |q| {
            QContent::Literal(String::from_utf8_lossy(q))
        }),
        map(quoted_pair::<P>, QContent::QP),
    ))(input)
}

// quoted-string not surrounded by CFWS
fn _inner_quoted_string<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Vec<QContent<'_>>> {
    map(
        delimited(
            tag("\""),
            pair(many0(pair(opt(fws), qcontent::<P>)), opt(fws)),
            tag("\""),
        ),
        |(a, b)| {
            let mut out = Vec::with_capacity(a.len() * 2 + 1);
            for (ws, cont) in a {
                match (ws, &cont, out.last()) {
                    #[cfg(feature = "quoted-string-rfc2047")]
                    (_, QContent::EncodedWord(_), Some(QContent::EncodedWord(_))) => (),
                    (Some(ws), _, _) => {
                        out.push(QContent::Literal(ws));
                    }
                    _ => (),
                }
                out.push(cont);
            }
            if let Some(x) = b {
                out.push(QContent::Literal(x))
            }
            out
        },
    )(input)
}

pub(crate) fn quoted_string<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, QuotedString> {
    map(
        delimited(opt(cfws::<P>), _inner_quoted_string::<P>, opt(cfws::<P>)),
        |qc| QuotedString(concat_qs(qc.into_iter())),
    )(input)
}

/// A single mailbox with an optional display name.
#[derive(Clone, Debug, PartialEq)]
pub struct Mailbox {
    /// The display name.
    pub dname: Option<String>,
    /// The address of this mailbox.
    pub address: types::Mailbox,
}

/// A group of many [`Mailbox`].
#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    /// This group's display name.
    pub dname: String,
    /// The members of this group. May be empty.
    pub members: Vec<Mailbox>,
}

/// An address is either a single [`Mailbox`] or a [`Group`].
#[derive(Clone, Debug, PartialEq)]
pub enum Address {
    /// Single [`Mailbox`].
    Mailbox(Mailbox),
    /// [`Group`] of many [`Mailbox`].
    Group(Group),
}

#[derive(Debug)]
enum QContent<'a> {
    Literal(Cow<'a, str>),
    #[cfg(feature = "quoted-string-rfc2047")]
    EncodedWord(EncodedWord<'a>),
    QP(char),
}

#[derive(Clone, Debug)]
enum Text<'a> {
    Literal(String),
    Atom(&'a str),
}

impl<'a> From<&'a Text<'a>> for &'a str {
    fn from(t: &'a Text<'a>) -> &'a str {
        match t {
            Text::Literal(s) => s,
            Text::Atom(s) => s,
        }
    }
}

fn concat_qs<'a, A: Iterator<Item = QContent<'a>>>(input: A) -> String {
    let mut out = String::new();

    for qc in input {
        match qc {
            QContent::Literal(lit) => out.push_str(&lit),
            #[cfg(feature = "quoted-string-rfc2047")]
            QContent::EncodedWord(ew) => out.push_str(&ew.decode()),
            QContent::QP(c) => out.push(c),
        }
    }
    out
}

fn _single_char(len: usize) -> impl Fn(&[u8]) -> NomResult<'_, char> {
    move |input| {
        map_opt(take(len), |c| {
            str::from_utf8(c).ok().and_then(|c| {
                if c.len() == len && c.chars().count() == 1 {
                    c.chars().next()
                } else {
                    None
                }
            })
        })(input)
    }
}

pub(crate) fn utf8_non_ascii(input: &[u8]) -> NomResult<'_, char> {
    alt((_single_char(4), _single_char(3), _single_char(2)))(input)
}

pub(crate) fn dot_atom<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, DotAtom> {
    map(
        delimited(
            opt(cfws::<P>),
            recognize(pair(
                recognize_many1(P::atext),
                recognize_many0(pair(tag("."), recognize_many1(P::atext))),
            )),
            opt(cfws::<P>),
        ),
        |a| (DotAtom(str::from_utf8(a).unwrap().into())),
    )(input)
}

pub(crate) fn atom<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, &[u8]> {
    delimited(opt(cfws::<P>), recognize_many1(P::atext), opt(cfws::<P>))(input)
}

pub(crate) fn _padded_encoded_word<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, EncodedWord<'_>> {
    delimited(opt(cfws::<P>), encoded_word, opt(cfws::<P>))(input)
}

fn word<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Text<'_>> {
    alt((
        map(_padded_encoded_word::<P>, |w| {
            Text::Literal(w.decode().into_owned())
        }),
        map(atom::<P>, |x| Text::Atom(str::from_utf8(x).unwrap())),
        map(quoted_string::<P>, |qs| Text::Literal(qs.0)),
    ))(input)
}

fn _concat_atom_and_qs<'a, A>(input: A) -> String
where
    A: Iterator<Item = Text<'a>>,
{
    let mut iter = input.peekable();
    let mut out = String::new();

    while let Some(cur) = iter.next() {
        match (cur, iter.peek()) {
            (Text::Atom(v), Some(_)) => {
                out.push_str(v);
                out.push(' ')
            }
            (_, Some(Text::Atom(v))) => {
                out.push_str(v);
                out.push(' ')
            }
            (ref t1, _) => out.push_str(t1.into()),
        };
    }

    out
}

fn display_name<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, String> {
    map(many1(word::<P>), |words| {
        _concat_atom_and_qs(words.into_iter())
    })(input)
}

pub(crate) fn local_part<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, LocalPart> {
    alt((
        map(dot_atom::<P>, |a| a.into()),
        map(quoted_string::<P>, LocalPart::Quoted),
    ))(input)
}

pub(crate) fn domain_literal<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, AddressLiteral> {
    map(
        delimited(
            pair(opt(cfws::<P>), tag("[")),
            pair(many0(pair(ofws, recognize_many1(P::dtext))), ofws),
            pair(tag("]"), opt(cfws::<P>)),
        ),
        |(a, b)| {
            let mut out: String = a
                .iter()
                .flat_map(|(x, y)| x.chars().chain(str::from_utf8(y).unwrap().chars()))
                .collect();
            out.push_str(&b);
            let literal = AddressLiteral::FreeForm(out);
            literal.upgrade().unwrap_or(literal)
        },
    )(input)
}

pub(crate) fn _domain<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Domain> {
    map(dot_atom::<P>, |a| Domain(a.0))(input)
}

pub(crate) fn domain<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, DomainPart> {
    alt((
        map(_domain::<P>, DomainPart::Domain),
        map(domain_literal::<P>, DomainPart::Address),
    ))(input)
}

pub(crate) fn addr_spec<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, types::Mailbox> {
    map(
        separated_pair(local_part::<P>, tag("@"), domain::<P>),
        |(lp, domain)| types::Mailbox(lp, domain),
    )(input)
}

fn angle_addr<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, types::Mailbox> {
    delimited(
        pair(opt(cfws::<P>), tag("<")),
        addr_spec::<P>,
        pair(tag(">"), opt(cfws::<P>)),
    )(input)
}

fn name_addr<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Mailbox> {
    map(
        pair(opt(display_name::<P>), angle_addr::<P>),
        |(dname, address)| Mailbox { dname, address },
    )(input)
}

fn mailbox<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Mailbox> {
    alt((
        name_addr::<P>,
        map(addr_spec::<P>, |a| Mailbox {
            dname: None,
            address: a,
        }),
    ))(input)
}

fn mailbox_list<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Vec<Mailbox>> {
    separated_list1(tag(","), mailbox::<P>)(input)
}

fn group_list<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Vec<Mailbox>> {
    alt((mailbox_list::<P>, map(cfws::<P>, |_| vec![])))(input)
}

fn group<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Group> {
    map(
        pair(
            terminated(display_name::<P>, tag(":")),
            terminated(opt(group_list::<P>), pair(tag(";"), opt(cfws::<P>))),
        ),
        |(dname, members)| Group {
            dname,
            members: members.unwrap_or_default(),
        },
    )(input)
}

fn address<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Address> {
    alt((
        map(mailbox::<P>, Address::Mailbox),
        map(group::<P>, Address::Group),
    ))(input)
}

fn address_list<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Vec<Address>> {
    separated_list1(tag(","), address::<P>)(input)
}

fn address_list_crlf<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Vec<Address>> {
    terminated(address_list::<P>, opt(crlf))(input)
}

fn address_crlf<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, Address> {
    terminated(address::<P>, opt(crlf))(input)
}

fn _8bit_char(input: &[u8]) -> NomResult<'_, char> {
    map(take1_filter(|c| c >= 0x80), |_| '\u{fffd}')(input)
}

/// Parse an unstructured header such as `"Subject:"`.
///
/// Returns a fully decoded string.
pub fn unstructured<P: Utf8Policy>(input: &[u8]) -> NomResult<'_, String> {
    map(
        pair(
            many0(alt((
                pair(
                    ofws,
                    fold_prefix0(
                        encoded_word,
                        preceded(fws, encoded_word),
                        String::new(),
                        |mut s, ew| {
                            s.push_str(&ew.decode());
                            s
                        },
                    ),
                ),
                pair(
                    ofws,
                    map(many1(alt((P::vchar, _8bit_char))), |c| {
                        c.iter().collect::<String>()
                    }),
                ),
            ))),
            many0(wsp),
        ),
        |(words, ws)| {
            let mut out = String::new();
            for (word_ws, word) in words {
                out.push_str(&word_ws);
                out.push_str(&word);
            }
            out.push_str(str::from_utf8(&ws).unwrap());
            out
        },
    )(input)
}

/// Parse the content of a `"From:"` header.
///
/// Returns a list of addresses, since [RFC 6854] allows multiple mail
/// authors.
///
/// [RFC 6854]: https://tools.ietf.org/html/rfc6854
pub fn from<P: Utf8Policy>(i: &[u8]) -> NomResult<'_, Vec<Address>> {
    address_list_crlf::<P>(i)
}

/// Parse the content of a `"Sender:"` header.
///
/// Returns a single address.
pub fn sender<P: Utf8Policy>(i: &[u8]) -> NomResult<'_, Address> {
    address_crlf::<P>(i)
}

/// Parse the content of a `"Reply-To:"` header.
///
/// Returns a list of addresses.
pub fn reply_to<P: Utf8Policy>(i: &[u8]) -> NomResult<'_, Vec<Address>> {
    address_list_crlf::<P>(i)
}
