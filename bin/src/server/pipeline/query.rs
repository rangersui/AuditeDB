use elastik_core::{InvalidTimelineCoordinate, TimelineCoordinate, ValidatedWorldPath};

pub(crate) const MAX_RAW_QUERY_BYTES: usize = 8192;
const TIMELINE_PAIR_LIMIT: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TimelineRequestMode {
    Current,
    Timeline(TimelineCoordinate),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TimelineQueryError {
    RawQueryTooLong,
    MalformedPercentEncoding,
    MalformedUtf8,
    TooManyTimelineFields,
    TimelineCoordinateRequiresMode,
    InvalidTimelineMode,
    DuplicateTimelineMode,
    MissingTimelineCoordinateField,
    DuplicateTimelineCoordinateField,
    UnknownTimelineCoordinateField,
    UnsupportedTimelineQueryField,
    TimelineWorldComesFromPath,
    InvalidTimelineSeq,
    InvalidTimelineCoordinate(InvalidTimelineCoordinate),
}

#[derive(Default)]
struct TimelineFields {
    mode: Option<String>,
    generation: Option<String>,
    seq: Option<String>,
    body_sha256: Option<String>,
    saw_timeline_field: bool,
    saw_unknown_timeline_field: bool,
    saw_timeline_world: bool,
    saw_unsupported_field: bool,
    saw_pre_timeline_ordinary_field: bool,
    timeline_pairs: usize,
}

pub(super) fn classify_raw_query(
    raw: Option<&str>,
    world: &ValidatedWorldPath,
) -> Result<TimelineRequestMode, TimelineQueryError> {
    let Some(raw) = raw else {
        return Ok(TimelineRequestMode::Current);
    };
    if raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(TimelineQueryError::RawQueryTooLong);
    }

    let mut fields = TimelineFields::default();
    for raw_pair in raw.split('&') {
        let (raw_key, raw_value) = raw_pair.split_once('=').unwrap_or((raw_pair, ""));
        let key = match decode_query_component(raw_key) {
            Ok(key) => key,
            Err(err)
                if fields.saw_timeline_field
                    || raw_key.starts_with("timeline")
                    || raw_key_may_be_timeline(raw_key) =>
            {
                return Err(err);
            }
            Err(_) => {
                fields.saw_pre_timeline_ordinary_field = true;
                continue;
            }
        };
        let timeline_key = key == "timeline" || key.starts_with("timeline-");

        if !fields.saw_timeline_field && !timeline_key {
            fields.saw_pre_timeline_ordinary_field = true;
        }
        if timeline_key {
            fields.saw_timeline_field = true;
            fields.timeline_pairs += 1;
        } else if fields.saw_timeline_field {
            fields.saw_unsupported_field = true;
        }

        match key.as_str() {
            "timeline" => {
                let value = decode_query_component(raw_value)?;
                set_once(
                    &mut fields.mode,
                    value,
                    TimelineQueryError::DuplicateTimelineMode,
                )?;
            }
            "timeline-generation" => {
                let value = decode_query_component(raw_value)?;
                set_once(
                    &mut fields.generation,
                    value,
                    TimelineQueryError::DuplicateTimelineCoordinateField,
                )?;
            }
            "timeline-seq" => {
                let value = decode_query_component(raw_value)?;
                set_once(
                    &mut fields.seq,
                    value,
                    TimelineQueryError::DuplicateTimelineCoordinateField,
                )?;
            }
            "timeline-body-sha256" => {
                let value = decode_query_component(raw_value)?;
                set_once(
                    &mut fields.body_sha256,
                    value,
                    TimelineQueryError::DuplicateTimelineCoordinateField,
                )?;
            }
            "timeline-world" => {
                fields.saw_timeline_world = true;
            }
            other if other.starts_with("timeline-") => {
                fields.saw_unknown_timeline_field = true;
            }
            _ => {}
        }
    }

    finish_classification(fields, world)
}

fn set_once(
    slot: &mut Option<String>,
    value: String,
    duplicate_error: TimelineQueryError,
) -> Result<(), TimelineQueryError> {
    if slot.is_some() {
        return Err(duplicate_error);
    }
    *slot = Some(value);
    Ok(())
}

fn raw_key_may_be_timeline(raw: &str) -> bool {
    let mut pos = 0;
    for byte in raw.bytes() {
        if pos >= b"timeline".len() {
            return byte == b'-' || byte == b'%';
        }
        if byte == b'%' {
            return true;
        }
        if byte != b"timeline"[pos] {
            return false;
        }
        pos += 1;
    }
    pos == b"timeline".len()
}

fn finish_classification(
    fields: TimelineFields,
    world: &ValidatedWorldPath,
) -> Result<TimelineRequestMode, TimelineQueryError> {
    if !fields.saw_timeline_field {
        return Ok(TimelineRequestMode::Current);
    }

    let Some(mode) = fields.mode else {
        return Err(TimelineQueryError::TimelineCoordinateRequiresMode);
    };
    if mode != "1" {
        return Err(TimelineQueryError::InvalidTimelineMode);
    }
    if fields.saw_timeline_world {
        return Err(TimelineQueryError::TimelineWorldComesFromPath);
    }
    if fields.saw_unknown_timeline_field {
        return Err(TimelineQueryError::UnknownTimelineCoordinateField);
    }
    if fields.saw_unsupported_field || fields.saw_pre_timeline_ordinary_field {
        return Err(TimelineQueryError::UnsupportedTimelineQueryField);
    }
    if fields.timeline_pairs > TIMELINE_PAIR_LIMIT {
        return Err(TimelineQueryError::TooManyTimelineFields);
    }

    let generation = fields
        .generation
        .ok_or(TimelineQueryError::MissingTimelineCoordinateField)?;
    let seq = fields
        .seq
        .ok_or(TimelineQueryError::MissingTimelineCoordinateField)?;
    let body_sha256 = fields
        .body_sha256
        .ok_or(TimelineQueryError::MissingTimelineCoordinateField)?;
    let seq = seq
        .parse::<i64>()
        .map_err(|_| TimelineQueryError::InvalidTimelineSeq)?;

    TimelineCoordinate::from_wire_parts(world.as_str(), generation, seq, body_sha256)
        .map(TimelineRequestMode::Timeline)
        .map_err(TimelineQueryError::InvalidTimelineCoordinate)
}

fn decode_query_component(raw: &str) -> Result<String, TimelineQueryError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(TimelineQueryError::MalformedPercentEncoding);
            }
            let hi = hex_value(bytes[i + 1])?;
            let lo = hex_value(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| TimelineQueryError::MalformedUtf8)
}

fn hex_value(byte: u8) -> Result<u8, TimelineQueryError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TimelineQueryError::MalformedPercentEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::pipeline::RawQuery;

    fn world(name: &str) -> ValidatedWorldPath {
        ValidatedWorldPath::new(name).unwrap()
    }

    fn classify(uri: &str) -> Result<TimelineRequestMode, TimelineQueryError> {
        RawQuery::from_uri(&uri.parse().unwrap()).classify_timeline_mode(&world("home/config"))
    }

    fn good_query() -> String {
        "timeline=1&timeline-generation=0123456789abcdef0123456789abcdef&timeline-seq=42&timeline-body-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned()
    }

    #[test]
    fn unrelated_query_is_current() {
        assert_eq!(
            classify("/home/config?a=1&b=2&c=3&d=4&e=5").unwrap(),
            TimelineRequestMode::Current
        );
    }

    #[test]
    fn valid_timeline_query_builds_untrusted_coordinate() {
        match classify(&format!("/home/config?{}", good_query())).unwrap() {
            TimelineRequestMode::Timeline(coordinate) => {
                assert_eq!(coordinate.world().as_str(), "home/config");
                assert_eq!(coordinate.seq().get(), 42);
            }
            TimelineRequestMode::Current => panic!("expected timeline mode"),
        }
    }

    #[test]
    fn raw_query_cap_returns_uri_too_long_error_kind() {
        let raw = format!("{}{}", "a=".repeat(4097), "x");
        let result = RawQuery::from_uri(&format!("/home/config?{raw}").parse().unwrap())
            .classify_timeline_mode(&world("home/config"));
        assert_eq!(result.unwrap_err(), TimelineQueryError::RawQueryTooLong);
    }

    #[test]
    fn malformed_percent_encoding_is_rejected() {
        assert_eq!(
            classify("/home/config?timeline%ZZ=1").unwrap_err(),
            TimelineQueryError::MalformedPercentEncoding
        );
    }

    #[test]
    fn unrelated_malformed_value_stays_current_compatible() {
        assert!(matches!(
            classify("/home/config?x=%ZZ").unwrap(),
            TimelineRequestMode::Current
        ));
    }

    #[test]
    fn unrelated_plain_malformed_key_stays_current_compatible() {
        assert!(matches!(
            classify("/home/config?x%ZZ=1").unwrap(),
            TimelineRequestMode::Current
        ));
    }

    #[test]
    fn malformed_timeline_like_key_is_rejected() {
        assert_eq!(
            classify("/home/config?time%ZZline=1").unwrap_err(),
            TimelineQueryError::MalformedPercentEncoding
        );
    }

    #[test]
    fn duplicate_detection_happens_after_decoding() {
        let query = "timeline=1&timeline-generation=0123456789abcdef0123456789abcdef&timeline%2dgeneration=0123456789abcdef0123456789abcdef&timeline-seq=42";
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::DuplicateTimelineCoordinateField
        );
    }

    #[test]
    fn encoded_timeline_mode_key_is_classified() {
        let query = good_query().replace("timeline=1", "timelin%65=1");
        match classify(&format!("/home/config?{query}")).unwrap() {
            TimelineRequestMode::Timeline(coordinate) => {
                assert_eq!(coordinate.world().as_str(), "home/config");
                assert_eq!(coordinate.seq().get(), 42);
            }
            TimelineRequestMode::Current => panic!("expected timeline mode"),
        }
    }

    #[test]
    fn encoded_timeline_stem_keys_are_classified() {
        let query = good_query().replace("timel", "time%6c");
        match classify(&format!("/home/config?{query}")).unwrap() {
            TimelineRequestMode::Timeline(coordinate) => assert_eq!(coordinate.seq().get(), 42),
            TimelineRequestMode::Current => panic!("encoded timeline keys must not be current"),
        }
    }

    #[test]
    fn encoded_coordinate_keys_are_classified() {
        let query = good_query()
            .replace("timeline-generation", "timeline%2dgeneration")
            .replace("timeline-seq", "timeline%2dseq")
            .replace("timeline-body-sha256", "timeline%2dbody-sha256");
        match classify(&format!("/home/config?{query}")).unwrap() {
            TimelineRequestMode::Timeline(coordinate) => {
                assert_eq!(coordinate.world().as_str(), "home/config");
                assert_eq!(coordinate.seq().get(), 42);
            }
            TimelineRequestMode::Current => panic!("expected timeline mode"),
        }
    }

    #[test]
    fn timeline_namespace_rejects_extra_ordinary_pair_as_unsupported() {
        let query = format!("{}&x=1", good_query());
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::UnsupportedTimelineQueryField
        );
    }

    #[test]
    fn timeline_world_error_is_not_masked_by_pair_cap() {
        let query = format!("{}&timeline-world=home/other", good_query());
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::TimelineWorldComesFromPath
        );
    }

    #[test]
    fn timeline_coordinate_fields_require_mode() {
        assert_eq!(
            classify("/home/config?timeline-generation=abc").unwrap_err(),
            TimelineQueryError::TimelineCoordinateRequiresMode
        );
    }

    #[test]
    fn duplicate_mode_is_rejected() {
        assert_eq!(
            classify("/home/config?timeline=1&timeline=1").unwrap_err(),
            TimelineQueryError::DuplicateTimelineMode
        );
    }

    #[test]
    fn invalid_mode_is_rejected() {
        assert_eq!(
            classify("/home/config?timeline=0").unwrap_err(),
            TimelineQueryError::InvalidTimelineMode
        );
    }

    #[test]
    fn missing_coordinate_field_is_rejected() {
        assert_eq!(
            classify("/home/config?timeline=1").unwrap_err(),
            TimelineQueryError::MissingTimelineCoordinateField
        );
    }

    #[test]
    fn unknown_timeline_field_is_rejected() {
        let query = good_query().replace("timeline-body-sha256", "timeline-extra");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::UnknownTimelineCoordinateField
        );
    }

    #[test]
    fn unsupported_non_timeline_field_is_rejected_in_timeline_mode() {
        let query = good_query().replace("timeline-body-sha256", "x");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::UnsupportedTimelineQueryField
        );
    }

    #[test]
    fn timeline_world_is_rejected() {
        let query = good_query().replace("timeline-body-sha256", "timeline-world");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::TimelineWorldComesFromPath
        );
    }

    #[test]
    fn non_integer_sequence_is_rejected_at_http_query_boundary() {
        let query = good_query().replace("timeline-seq=42", "timeline-seq=not-an-int");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::InvalidTimelineSeq
        );
    }

    #[test]
    fn core_coordinate_errors_remain_distinct() {
        let query = good_query().replace("timeline-seq=42", "timeline-seq=0");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::InvalidTimelineCoordinate(
                InvalidTimelineCoordinate::SeqNonPositive
            )
        );
    }

    #[test]
    fn negative_sequence_reaches_core_non_positive_coordinate_error() {
        let query = good_query().replace("timeline-seq=42", "timeline-seq=-1");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::InvalidTimelineCoordinate(
                InvalidTimelineCoordinate::SeqNonPositive
            )
        );
    }

    #[test]
    fn overflowing_sequence_is_rejected_at_http_query_boundary() {
        let query = good_query().replace("timeline-seq=42", "timeline-seq=9223372036854775808");
        assert_eq!(
            classify(&format!("/home/config?{query}")).unwrap_err(),
            TimelineQueryError::InvalidTimelineSeq
        );
    }

    #[test]
    fn memory_world_is_rejected_by_coordinate_constructor() {
        let result = RawQuery::from_uri(&format!("/tmp/config?{}", good_query()).parse().unwrap())
            .classify_timeline_mode(&world("tmp/config"));
        assert_eq!(
            result.unwrap_err(),
            TimelineQueryError::InvalidTimelineCoordinate(InvalidTimelineCoordinate::MemoryWorld)
        );
    }
}
