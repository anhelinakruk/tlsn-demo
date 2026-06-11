use std::{collections::HashMap, ops::Range};

use pest::{RuleType, iterators::Pair};
use thiserror::Error;

mod traversal;
mod types;

pub use types::Rule;

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("invalid syntax: {0}")]
    InvalidSyntax(String),

    #[error("unexpected rule: {0}")]
    UnexpectedRule(String),

    #[error("missing field: {0}")]
    MissingField(String),
}

impl<R: pest::RuleType> From<pest::error::Error<R>> for ParseError {
    fn from(err: pest::error::Error<R>) -> Self {
        Self::InvalidSyntax(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub trait HttpMessage {
    type Header;
    type Body;

    fn headers(&self) -> &HashMap<String, Vec<Self::Header>>;
    fn body(&self) -> &HashMap<String, Self::Body>;
}

pub(crate) trait RangeExtractor {
    fn extract_range(&self) -> Range<usize>;
}

impl<R: RuleType> RangeExtractor for Pair<'_, R> {
    fn extract_range(&self) -> Range<usize> {
        self.as_span().start()..self.as_span().end()
    }
}

pub trait JsonFieldRangeExt {
    fn adjust(&self, start_off: isize, end_off: isize) -> Range<usize>;
    fn extend_to(&self, end: usize) -> Range<usize>;
    fn span_to(&self, end: usize) -> Range<usize>;

    fn with_quotes_and_colon(&self) -> Range<usize> {
        self.adjust(-1, 2)
    }
    fn full_pair_quoted(&self, value: &Range<usize>) -> Range<usize> {
        self.extend_to(value.end + 1)
    }
    fn full_pair_unquoted(&self, value: &Range<usize>) -> Range<usize> {
        self.extend_to(value.end)
    }
    fn with_newline(&self) -> Range<usize> {
        self.adjust(0, 1)
    }
    fn header_full_range(&self, value: &Range<usize>) -> Range<usize> {
        self.span_to(value.end + 1)
    }
}

impl JsonFieldRangeExt for Range<usize> {
    fn adjust(&self, start_off: isize, end_off: isize) -> Range<usize> {
        (self.start as isize + start_off).max(0) as usize..(self.end as isize + end_off) as usize
    }
    fn extend_to(&self, end: usize) -> Range<usize> {
        self.start.saturating_sub(1)..end
    }
    fn span_to(&self, end: usize) -> Range<usize> {
        self.start..end
    }
}

pub mod standard {
    pub use super::types::{
        StandardBody as Body, StandardHeader as Header, StandardRequest as Request,
        StandardResponse as Response, parse_standard_request as parse_request,
        parse_standard_response as parse_response,
    };
}

pub mod redacted {
    pub use super::types::{
        RedactedBody as Body, RedactedHeader as Header, RedactedRequest as Request,
        RedactedResponse as Response, parse_redacted_request as parse_request,
        parse_redacted_response as parse_response,
    };
}
