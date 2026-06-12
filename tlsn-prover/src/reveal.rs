use std::ops::Range;

use tlsn::{config::prove::ProveConfigBuilder, transcript::TranscriptCommitConfigBuilder};
use tracing::info;

use crate::{
    Error,
    parser::{
        HttpMessage, JsonFieldRangeExt,
        standard::{Body, Header, Request as ParsedRequest, Response as ParsedResponse},
    },
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BodyFieldConfig {
    Quoted(String),
    Unquoted(String),
}

impl BodyFieldConfig {
    fn keypath(&self) -> &str {
        match self {
            Self::Quoted(s) | Self::Unquoted(s) => s,
        }
    }

    fn selection_range(&self, body_field: &Body) -> Range<usize> {
        match (self, body_field) {
            (Self::Quoted(_), Body::KeyValue { key, value }) => key.full_pair_quoted(value),
            (Self::Unquoted(_), Body::KeyValue { key, value }) => key.full_pair_unquoted(value),
            (_, Body::Value(range)) => range.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyValueCommitConfig {
    pub keypath: String,
    pub commitment_length: Option<usize>,
}

impl KeyValueCommitConfig {
    /// Range of bytes committed for the value. When `commitment_length` is set,
    /// the value range is padded to that fixed width (or kept as-is if already
    /// longer) so the commitment doesn't leak the value's actual length.
    fn value_range(&self, value: &Range<usize>) -> Range<usize> {
        match self.commitment_length {
            Some(len) if value.end - value.start < len => value.start..value.start + len,
            _ => value.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealConfig {
    pub reveal_headers: Vec<String>,
    pub commit_headers: Vec<String>,
    pub reveal_body_fields: Vec<BodyFieldConfig>,
    pub commit_body_fields: Vec<BodyFieldConfig>,
    pub reveal_keys_commit_values: Vec<KeyValueCommitConfig>,
}

#[derive(Debug, Clone, Copy)]
enum TranscriptDirection {
    Sent,
    Received,
}

impl TranscriptDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Sent => "request",
            Self::Received => "response",
        }
    }

    fn apply_reveal(self, builder: &mut ProveConfigBuilder<'_>, range: &Range<usize>) -> Result<(), Error> {
        match self {
            Self::Sent => builder.reveal_sent(range)?,
            Self::Received => builder.reveal_recv(range)?,
        };
        Ok(())
    }

    fn apply_commit(self, builder: &mut TranscriptCommitConfigBuilder, range: &Range<usize>) -> Result<(), Error> {
        match self {
            Self::Sent => builder.commit_sent(range)?,
            Self::Received => builder.commit_recv(range)?,
        };
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum DisclosureAction {
    Reveal,
    Commit,
}

impl DisclosureAction {
    fn label(self) -> &'static str {
        match self {
            Self::Reveal => "reveal",
            Self::Commit => "commit",
        }
    }
}

struct DisclosureBuilders<'b, 't> {
    prove_config: &'b mut ProveConfigBuilder<'t>,
    transcript_commit_config: &'b mut TranscriptCommitConfigBuilder<'t>,
}

fn apply_disclosure(
    direction: TranscriptDirection,
    action: DisclosureAction,
    target: &str,
    label: &str,
    range: &Range<usize>,
    source: &[u8],
    builders: &mut DisclosureBuilders<'_, '_>,
) -> Result<(), Error> {
    match action {
        DisclosureAction::Reveal => direction.apply_reveal(builders.prove_config, range)?,
        DisclosureAction::Commit => direction.apply_commit(builders.transcript_commit_config, range)?,
    }
    info!(
        direction = direction.label(),
        action = action.label(),
        target,
        label,
        range_start = range.start,
        range_end = range.end,
        preview = %preview_range(source, range),
        "prover.reveal.range"
    );
    Ok(())
}

fn preview_range(source: &[u8], range: &Range<usize>) -> String {
    const MAX: usize = 96;
    source.get(range.clone()).map_or_else(
        || "<out-of-bounds>".to_string(),
        |slice| {
            let s = if slice.len() > MAX { &slice[..MAX] } else { slice };
            String::from_utf8_lossy(s)
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t")
        },
    )
}

fn apply_rules<R, T>(
    rules: &[R],
    mut find: impl FnMut(&R) -> Result<T, Error>,
    mut disclose: impl FnMut(&R, T) -> Result<(), Error>,
) -> Result<(), Error> {
    rules.iter().try_for_each(|rule| {
        let target = find(rule)?;
        disclose(rule, target)
    })
}

fn apply_message_reveal_config<M>(
    direction: TranscriptDirection,
    message: &M,
    source: &[u8],
    start_line_label: &str,
    start_line_range: Range<usize>,
    builders: &mut DisclosureBuilders<'_, '_>,
    config: &RevealConfig,
) -> Result<(), Error>
where
    M: HttpMessage<Header = Header, Body = Body>,
{
    apply_disclosure(direction, DisclosureAction::Reveal, "line", start_line_label, &start_line_range, source, builders)?;

    for (names, action) in [
        (&config.reveal_headers, DisclosureAction::Reveal),
        (&config.commit_headers, DisclosureAction::Commit),
    ] {
        apply_rules(
            names,
            |name| {
                message.headers().get(&name.to_lowercase()).ok_or_else(|| Error::RevealRuleNotMatched {
                    direction: direction.label(),
                    target: "header",
                    rule: name.clone(),
                })
            },
            |name, headers| {
                headers.iter().enumerate().try_for_each(|(idx, header)| {
                    let range = header.name.header_full_range(&header.value);
                    apply_disclosure(direction, action, "header", &format!("{name}[{idx}]"), &range, source, builders)
                })
            },
        )?;
    }

    for (fields, action) in [
        (&config.reveal_body_fields, DisclosureAction::Reveal),
        (&config.commit_body_fields, DisclosureAction::Commit),
    ] {
        apply_rules(
            fields,
            |field| {
                message.body().get(field.keypath()).ok_or_else(|| Error::RevealRuleNotMatched {
                    direction: direction.label(),
                    target: "body",
                    rule: field.keypath().to_string(),
                })
            },
            |field, body_field| {
                let range = field.selection_range(body_field);
                apply_disclosure(direction, action, "body", field.keypath(), &range, source, builders)
            },
        )?;
    }

    apply_rules(
        &config.reveal_keys_commit_values,
        |rule| {
            message.body().get(&rule.keypath)
                .ok_or_else(|| Error::RevealRuleNotMatched {
                    direction: direction.label(),
                    target: "body-key-value",
                    rule: rule.keypath.clone(),
                })
                .and_then(|body_field| match body_field {
                    Body::KeyValue { key, value } => Ok((key, value)),
                    Body::Value(_) => Err(Error::RevealStructureMismatch {
                        rule: rule.keypath.clone(),
                        expected: "key-value",
                        actual: "value",
                    }),
                })
        },
        |rule, (key, value)| {
            apply_disclosure(direction, DisclosureAction::Reveal, "body-key", &rule.keypath, &key.with_quotes_and_colon(), source, builders)?;
            let committed = rule.value_range(value);
            apply_disclosure(direction, DisclosureAction::Commit, "body-value", &rule.keypath, &committed, source, builders)
        },
    )
}

pub(crate) fn reveal_request<'t>(
    request: &[u8],
    prove_config: &mut ProveConfigBuilder<'t>,
    transcript_commit_config: &mut TranscriptCommitConfigBuilder<'t>,
    config: &RevealConfig,
) -> Result<(), Error> {
    let mut builders = DisclosureBuilders { prove_config, transcript_commit_config };

    if config.reveal_headers.is_empty()
        && config.commit_headers.is_empty()
        && config.reveal_body_fields.is_empty()
        && config.commit_body_fields.is_empty()
        && config.reveal_keys_commit_values.is_empty()
    {
        return apply_disclosure(
            TranscriptDirection::Sent,
            DisclosureAction::Reveal,
            "message", "full",
            &(0..request.len()),
            request,
            &mut builders,
        );
    }

    let raw = String::from_utf8(request.to_vec())?;
    let parsed: ParsedRequest = raw.parse()?;
    let start_range = parsed.method.start..parsed.protocol_version.with_newline().end;
    apply_message_reveal_config(TranscriptDirection::Sent, &parsed, request, "request-line", start_range, &mut builders, config)
}

pub(crate) fn reveal_response<'t>(
    response: &[u8],
    prove_config: &mut ProveConfigBuilder<'t>,
    transcript_commit_config: &mut TranscriptCommitConfigBuilder<'t>,
    config: &RevealConfig,
) -> Result<(), Error> {
    let mut builders = DisclosureBuilders { prove_config, transcript_commit_config };

    let raw = String::from_utf8(response.to_vec())?;
    let parsed: ParsedResponse = raw.parse()?;
    let start_range = parsed.protocol_version.start..parsed.status.with_newline().end;
    apply_message_reveal_config(TranscriptDirection::Received, &parsed, response, "status-line", start_range, &mut builders, config)
}
