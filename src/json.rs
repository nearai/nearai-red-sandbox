//! Strict JSON helpers shared by attestation and the forwarder.
//!
//! Where one value binds evidence to a session (a nonce, a model, a chat ID)
//! a repeated key is refused rather than resolved, because parsers disagree
//! on whether the first or the last one wins.

use serde::de::{IgnoredAny, MapAccess, Visitor};

/// The top-level string `key` of a JSON object. A repeated `key` is refused:
/// parsers disagree on which one wins.
pub(crate) fn top_level_string(body: &[u8], key: &str) -> Option<String> {
    struct Found(Option<String>);
    struct Seek<'k>(&'k str);
    impl<'de> serde::de::DeserializeSeed<'de> for Seek<'_> {
        type Value = Found;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Found, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Seek<'_> {
        type Value = Found;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Found, A::Error> {
            let mut found = None;
            while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                if k == self.0 {
                    if found.is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                    found = Some(map.next_value::<String>()?);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(Found(found))
        }
    }
    let mut de = serde_json::Deserializer::from_slice(body);
    let found = serde::de::DeserializeSeed::deserialize(Seek(key), &mut de).ok()?;
    de.end().ok()?;
    found.0
}
