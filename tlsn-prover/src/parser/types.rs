use std::{collections::HashMap, ops::Range, str::FromStr};

use pest::{Parser as _, RuleType, iterators::Pair};

use super::{
    HttpMessage, ParseError, RangeExtractor, Result,
    traversal::{HeaderValue, parse_headers, parse_redacted_body, parse_standard_body},
};

mod grammar {
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "./parser/grammar.pest"]
    pub struct Parser;
}

pub use grammar::Rule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<V> {
    pub name: Range<usize>,
    pub value: V,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body<V> {
    KeyValue { key: Range<usize>, value: V },
    Value(Range<usize>),
}

#[derive(Debug, Clone)]
pub struct Request<H, B> {
    pub method: Range<usize>,
    pub url: Range<usize>,
    pub protocol_version: Range<usize>,
    pub headers: HashMap<String, Vec<H>>,
    pub body: HashMap<String, B>,
}

#[derive(Debug, Clone)]
pub struct Response<H, B> {
    pub protocol_version: Range<usize>,
    pub status_code: Range<usize>,
    pub status: Range<usize>,
    pub headers: HashMap<String, Vec<H>>,
    pub body: HashMap<String, B>,
}

impl<H, B> HttpMessage for Request<H, B> {
    type Header = H;
    type Body = B;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>> {
        &self.headers
    }
    fn body(&self) -> &HashMap<String, Self::Body> {
        &self.body
    }
}

impl<H, B> HttpMessage for Response<H, B> {
    type Header = H;
    type Body = B;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>> {
        &self.headers
    }
    fn body(&self) -> &HashMap<String, Self::Body> {
        &self.body
    }
}

pub type StandardHeader = Header<Range<usize>>;
pub type StandardBody = Body<Range<usize>>;
pub type StandardRequest = Request<StandardHeader, StandardBody>;
pub type StandardResponse = Response<StandardHeader, StandardBody>;

pub type RedactedHeader = Header<Option<Range<usize>>>;
pub type RedactedBody = Body<Option<Range<usize>>>;
pub type RedactedRequest = Request<RedactedHeader, RedactedBody>;
pub type RedactedResponse = Response<RedactedHeader, RedactedBody>;

pub(super) fn assert_rule<R: RuleType + PartialEq>(
    pair: &Pair<'_, R>,
    expected: R,
    field: &str,
) -> Result<()> {
    if pair.as_rule() != expected {
        return Err(ParseError::UnexpectedRule(format!(
            "expected {field}, got {:?}",
            pair.as_rule()
        )));
    }
    Ok(())
}

pub(super) fn assert_end_of_iterator<'a, R: RuleType>(
    iter: &mut impl Iterator<Item = Pair<'a, R>>,
    context: &str,
) -> Result<()> {
    if iter.next().is_some() {
        return Err(ParseError::UnexpectedRule(format!(
            "expected end of iterator in {context}"
        )));
    }
    Ok(())
}

fn parse_three_field_line<R: RuleType + PartialEq>(
    line: Pair<'_, R>,
    line_rule: R,
    line_label: &'static str,
    fields: [(R, &'static str); 3],
) -> Result<(Range<usize>, Range<usize>, Range<usize>)> {
    assert_rule(&line, line_rule, line_label)?;
    let mut inner = line.into_inner();
    let [a, b, c] = fields.map(|(rule, label)| {
        inner
            .next()
            .ok_or_else(|| ParseError::MissingField(label.to_string()))
            .and_then(|pair| {
                assert_rule(&pair, rule, label)?;
                Ok(pair)
            })
    });
    let a = a?;
    let b = b?;
    let c = c?;
    assert_end_of_iterator(&mut inner, line_label)?;
    Ok((a.extract_range(), b.extract_range(), c.extract_range()))
}

fn parse_request_inner<V, B>(
    input: &str,
    parse_body: impl FnOnce(pest::iterators::Pairs<'_, Rule>) -> Result<HashMap<String, B>>,
) -> Result<Request<Header<V>, B>>
where
    V: HeaderValue,
{
    let mut pairs = grammar::Parser::parse(Rule::request, input)?;
    let first_line_pair = pairs
        .next()
        .ok_or_else(|| ParseError::MissingField("first line".to_string()))?;
    let headers_pair = pairs
        .next()
        .ok_or_else(|| ParseError::MissingField("headers section".to_string()))?;

    let (method, url, protocol_version) = parse_three_field_line(
        first_line_pair,
        Rule::request_line,
        "request_line",
        [
            (Rule::method, "method"),
            (Rule::url, "url"),
            (Rule::protocol_version, "protocol_version"),
        ],
    )?;
    let headers = parse_headers::<V>(headers_pair)?;
    let body = parse_body(pairs)?;
    Ok(Request { method, url, protocol_version, headers, body })
}

fn parse_response_inner<V, B>(
    input: &str,
    parse_body: impl FnOnce(pest::iterators::Pairs<'_, Rule>) -> Result<HashMap<String, B>>,
) -> Result<Response<Header<V>, B>>
where
    V: HeaderValue,
{
    let mut pairs = grammar::Parser::parse(Rule::response, input)?;
    let first_line_pair = pairs
        .next()
        .ok_or_else(|| ParseError::MissingField("first line".to_string()))?;
    let headers_pair = pairs
        .next()
        .ok_or_else(|| ParseError::MissingField("headers section".to_string()))?;

    let (protocol_version, status_code, status) = parse_three_field_line(
        first_line_pair,
        Rule::status_line,
        "status_line",
        [
            (Rule::protocol_version, "protocol_version"),
            (Rule::status_code, "status_code"),
            (Rule::status, "status"),
        ],
    )?;
    let headers = parse_headers::<V>(headers_pair)?;
    let body = parse_body(pairs)?;
    Ok(Response { protocol_version, status_code, status, headers, body })
}

pub fn parse_standard_request(input: &str) -> Result<StandardRequest> {
    parse_request_inner(input, parse_standard_body)
}

pub fn parse_standard_response(input: &str) -> Result<StandardResponse> {
    parse_response_inner(input, parse_standard_body)
}

pub fn parse_redacted_request(input: &str) -> Result<RedactedRequest> {
    parse_request_inner(input, parse_redacted_body)
}

pub fn parse_redacted_response(input: &str) -> Result<RedactedResponse> {
    parse_response_inner(input, parse_redacted_body)
}

impl FromStr for StandardRequest {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self> { parse_standard_request(s) }
}

impl FromStr for StandardResponse {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self> { parse_standard_response(s) }
}

impl FromStr for RedactedRequest {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self> { parse_redacted_request(s) }
}

impl FromStr for RedactedResponse {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self> { parse_redacted_response(s) }
}
