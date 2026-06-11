use std::{collections::HashMap, fmt, ops::Range};

use pest::iterators::{Pair, Pairs};

use super::{
    ParseError, RangeExtractor, Result,
    types::{Body, Header, Rule, assert_end_of_iterator, assert_rule},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone, Default)]
struct PathStack {
    segments: Vec<PathSegment>,
}

impl PathStack {
    fn push(&mut self, segment: PathSegment) {
        self.segments.push(segment);
    }

    fn pop(&mut self) -> Option<PathSegment> {
        self.segments.pop()
    }
}

impl fmt::Display for PathStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for segment in &self.segments {
            match segment {
                PathSegment::Key(k) => write!(f, ".{k}")?,
                PathSegment::Index(i) => write!(f, "[{i}]")?,
            }
        }
        Ok(())
    }
}

pub trait HeaderValue: Sized {
    fn parse<'a>(inner: &mut impl Iterator<Item = Pair<'a, Rule>>) -> Result<Self>;
}

impl HeaderValue for Range<usize> {
    fn parse<'a>(inner: &mut impl Iterator<Item = Pair<'a, Rule>>) -> Result<Self> {
        let value_pair = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("header value".to_string()))?;
        assert_rule(&value_pair, Rule::header_value, "header_value")?;
        Ok(value_pair.extract_range())
    }
}

impl HeaderValue for Option<Range<usize>> {
    fn parse<'a>(inner: &mut impl Iterator<Item = Pair<'a, Rule>>) -> Result<Self> {
        inner
            .next()
            .map(|value_pair| {
                assert_rule(&value_pair, Rule::header_value, "header_value")?;
                Ok(value_pair.extract_range())
            })
            .transpose()
    }
}

pub fn parse_headers<V>(headers_pair: Pair<'_, Rule>) -> Result<HashMap<String, Vec<Header<V>>>>
where
    V: HeaderValue,
{
    assert_rule(&headers_pair, Rule::headers, "headers")?;
    headers_pair.into_inner().map(parse_header::<V>).try_fold(
        HashMap::<String, Vec<Header<V>>>::new(),
        |mut acc, parsed| {
            let (name, header) = parsed?;
            acc.entry(name).or_default().push(header);
            Ok(acc)
        },
    )
}

fn parse_header<V>(pair: Pair<'_, Rule>) -> Result<(String, Header<V>)>
where
    V: HeaderValue,
{
    assert_rule(&pair, Rule::header, "header")?;
    let mut inner = pair.into_inner();
    let name_pair = inner
        .next()
        .ok_or_else(|| ParseError::MissingField("header name".to_string()))?;
    assert_rule(&name_pair, Rule::header_name, "header_name")?;
    let name = name_pair.as_str().to_lowercase();
    let value = V::parse(&mut inner)?;
    assert_end_of_iterator(&mut inner, "header")?;
    Ok((
        name,
        Header {
            name: name_pair.extract_range(),
            value,
        },
    ))
}

pub fn parse_standard_body(
    mut pairs: Pairs<'_, Rule>,
) -> Result<HashMap<String, Body<Range<usize>>>> {
    if let Some(body_pair) = pairs.next()
        && (body_pair.as_rule() == Rule::object || body_pair.as_rule() == Rule::array)
    {
        return StandardBodyTraverser::new(body_pair).traverse();
    }
    Ok(HashMap::new())
}

struct StandardBodyTraverser<'a> {
    root: Pair<'a, Rule>,
    body: HashMap<String, Body<Range<usize>>>,
    path: PathStack,
}

impl<'a> StandardBodyTraverser<'a> {
    fn new(root: Pair<'a, Rule>) -> Self {
        let mut body = HashMap::new();
        body.insert(String::new(), Body::Value(root.extract_range()));
        Self {
            root,
            body,
            path: PathStack::default(),
        }
    }

    fn traverse(mut self) -> Result<HashMap<String, Body<Range<usize>>>> {
        self.traverse_value(self.root.clone())?;
        Ok(self.body)
    }

    fn traverse_value(&mut self, value: Pair<'_, Rule>) -> Result<()> {
        let rule = value.as_rule();
        if rule == Rule::object {
            self.traverse_object(value)?;
        } else if rule == Rule::array {
            self.traverse_array(value)?;
        }
        self.path.pop();
        Ok(())
    }

    fn traverse_object(&mut self, value: Pair<'_, Rule>) -> Result<()> {
        assert_rule(&value, Rule::object, "object")?;
        for pair in value.into_inner() {
            assert_rule(&pair, Rule::pair, "pair")?;
            let mut inner = pair.into_inner();
            let key_pair = inner
                .next()
                .ok_or_else(|| ParseError::MissingField("object key".to_string()))?;
            let value_pair = inner
                .next()
                .ok_or_else(|| ParseError::MissingField("object value".to_string()))?;
            assert_end_of_iterator(&mut inner, "pair")?;

            self.path
                .push(PathSegment::Key(key_pair.as_str().to_string()));
            self.body.insert(
                self.path.to_string(),
                Body::KeyValue {
                    key: key_pair.extract_range(),
                    value: value_pair.extract_range(),
                },
            );
            self.traverse_value(value_pair)?;
        }
        Ok(())
    }

    fn traverse_array(&mut self, value: Pair<'_, Rule>) -> Result<()> {
        assert_rule(&value, Rule::array, "array")?;
        for (idx, pair) in value.into_inner().enumerate() {
            self.path.push(PathSegment::Index(idx));
            self.body
                .insert(self.path.to_string(), Body::Value(pair.extract_range()));
            self.traverse_value(pair)?;
        }
        Ok(())
    }
}

pub fn parse_redacted_body(
    pairs: Pairs<'_, Rule>,
) -> Result<HashMap<String, Body<Option<Range<usize>>>>> {
    let mut body = HashMap::new();
    let mut path = PathStack::default();
    for pair in pairs {
        if pair.as_rule() != Rule::pair_redacted {
            break;
        }
        let mut inner = pair.into_inner();
        let key_pair = inner
            .next()
            .ok_or_else(|| ParseError::MissingField("key in pair".to_string()))?;
        let value = inner.next().map(|v| v.extract_range());
        assert_end_of_iterator(&mut inner, "pair")?;

        path.push(PathSegment::Key(key_pair.as_str().to_string()));
        body.insert(
            path.to_string(),
            Body::KeyValue {
                key: key_pair.extract_range(),
                value,
            },
        );
        path.pop();
    }
    Ok(body)
}
