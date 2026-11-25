//! The signed attestation policy feed: one document per NEAR AI environment,
//! signed by CI or by the offline recovery key, that endorses compose hashes
//! beyond the compiled-in pins and revokes hashes, pins included.
//!
//! The signature is checked over the document bytes exactly as fetched,
//! before anything is parsed, as `latest.json` is.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::attest::{Match, Policy, Role};
use crate::inference::NearEnvironment;

/// `issued` may be at most this far ahead of the local clock.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// The longest validity window `rts` accepts, `expires - issued`.
pub const MAX_VALIDITY_SECS: u64 = 7 * 86_400;

/// One or two comma-separated 64-hex Ed25519 public keys (either case) to
/// bytes, with the count. Panics otherwise, which is a compile error when
/// evaluated for [`FEED_KEYS`].
pub const fn parse_feed_keys(s: &str) -> ([[u8; 32]; 2], usize) {
    let s = s.as_bytes();
    let mut out = [[0u8; 32]; 2];
    let n = match s.len() {
        64 => 1,
        129 if s[64] == b',' => 2,
        _ => panic!(
            "RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX must be one or two comma-separated keys of 64 hex characters"
        ),
    };
    let mut k = 0;
    while k < n {
        let base = k * 65;
        let mut i = 0;
        while i < 32 {
            out[k][i] = (key_nibble(s[base + 2 * i]) << 4) | key_nibble(s[base + 2 * i + 1]);
            i += 1;
        }
        k += 1;
    }
    (out, n)
}

const fn key_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!(
            "RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX must be one or two comma-separated keys of 64 hex characters"
        ),
    }
}

const PARSED_FEED_KEYS: ([[u8; 32]; 2], usize) =
    match option_env!("RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX") {
        Some(s) => parse_feed_keys(s),
        None => ([[0u8; 32]; 2], 0),
    };

/// The Ed25519 public keys that sign the policy feed (the CI key and the
/// offline recovery key), from the build-time environment. Empty for a build
/// without them, which never fetches the feed. A malformed value fails const
/// evaluation: a compile error.
pub const FEED_KEYS: &[[u8; 32]] = PARSED_FEED_KEYS.0.split_at(PARSED_FEED_KEYS.1).0;

/// A feed document that verified and passed the spec's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedDocument {
    pub environment: NearEnvironment,
    pub version: u64,
    /// Unix seconds.
    pub issued: u64,
    /// Unix seconds.
    pub expires: u64,
    /// Endorsements with a `match` this build knows; others are skipped.
    pub entries: Vec<(Role, Match, [u8; 32])>,
    pub revoked: BTreeSet<[u8; 32]>,
}

/// No deny_unknown_fields: a later document may add fields, and `app_name`,
/// `first_seen` and `endorsed_by` are for people.
#[derive(Deserialize)]
struct RawDocument {
    schema: u64,
    environment: String,
    version: u64,
    issued: chrono::DateTime<chrono::Utc>,
    expires: chrono::DateTime<chrono::Utc>,
    entries: Vec<RawEntry>,
    revoked: Vec<String>,
}

#[derive(Deserialize)]
struct RawEntry {
    role: Role,
    /// A string, so an unknown normalization is skipped rather than refused.
    #[serde(rename = "match")]
    match_: String,
    sha256: String,
}

fn environment_name(env: NearEnvironment) -> &'static str {
    match env {
        NearEnvironment::Production => "production",
        NearEnvironment::Staging => "staging",
    }
}

/// Signature first (exact bytes, `verify_strict`, either key), then parse,
/// then the spec's rules: schema, environment, clock window, rollback mark,
/// roles and lowercase hex digests. `now` is unix seconds.
pub fn verify_document(
    doc: &[u8],
    sig_b64: &[u8],
    keys: &[[u8; 32]],
    env: NearEnvironment,
    now: u64,
    high_water: u64,
) -> Result<FeedDocument, String> {
    let name = environment_name(env);
    let ctx = format!("attestation policy {name}.json");

    let sig_b64 = sig_b64.strip_suffix(b"\n").unwrap_or(sig_b64);
    let raw = STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("{ctx}.sig: signature is not base64: {e}"))?;
    let raw = <[u8; 64]>::try_from(raw.as_slice())
        .map_err(|_| format!("{ctx}.sig: signature is not 64 bytes ({})", raw.len()))?;
    if keys.is_empty() {
        return Err(format!("{ctx}: no feed key is compiled in"));
    }
    let signature = Signature::from_bytes(&raw);
    let verified = keys.iter().any(|k| {
        VerifyingKey::from_bytes(k).is_ok_and(|k| k.verify_strict(doc, &signature).is_ok())
    });
    if !verified {
        return Err(format!(
            "{ctx}: signature does not verify with any feed key"
        ));
    }

    let d: RawDocument = serde_json::from_slice(doc).map_err(|e| format!("{ctx}: {e}"))?;
    if d.schema != 1 {
        return Err(format!("{ctx}: schema {} is not 1", d.schema));
    }
    if d.environment != name {
        return Err(format!(
            "{ctx}: environment {:?} is not {name:?}",
            d.environment
        ));
    }
    let issued = u64::try_from(d.issued.timestamp())
        .map_err(|_| format!("{ctx}: issued {} is before 1970", d.issued))?;
    let expires = u64::try_from(d.expires.timestamp())
        .map_err(|_| format!("{ctx}: expires {} is before 1970", d.expires))?;
    if expires <= issued {
        return Err(format!(
            "{ctx}: expires {} is not after issued {}",
            d.expires, d.issued
        ));
    }
    if expires - issued > MAX_VALIDITY_SECS {
        return Err(format!(
            "{ctx}: validity from {} to {} is over 7 days",
            d.issued, d.expires
        ));
    }
    if issued > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(format!(
            "{ctx}: issued {} is more than 5 minutes in the future",
            d.issued
        ));
    }
    if now >= expires {
        return Err(format!("{ctx}: expired at {}", d.expires));
    }
    if d.version < high_water {
        return Err(format!(
            "{ctx}: version {} is below the last accepted version {high_water}",
            d.version
        ));
    }

    let mut entries = Vec::new();
    let mut roles = std::collections::BTreeMap::new();
    for e in &d.entries {
        let hash = parse_sha256(&e.sha256).ok_or_else(|| {
            format!(
                "{ctx}: entry sha256 {:?} is not 64 lowercase hex characters",
                e.sha256
            )
        })?;
        let m = match e.match_.as_str() {
            "exact" => Match::Exact,
            "instance-label-v1" => Match::InstanceLabelV1,
            _ => continue,
        };
        match roles.insert((m, hash), e.role) {
            Some(prev) if prev != e.role => {
                return Err(format!("{ctx}: {} is endorsed under two roles", e.sha256));
            }
            Some(_) => {}
            None => entries.push((e.role, m, hash)),
        }
    }
    let mut revoked = BTreeSet::new();
    for h in &d.revoked {
        revoked.insert(parse_sha256(h).ok_or_else(|| {
            format!("{ctx}: revoked sha256 {h:?} is not 64 lowercase hex characters")
        })?);
    }

    Ok(FeedDocument {
        environment: env,
        version: d.version,
        issued,
        expires,
        entries,
        revoked,
    })
}

/// 64 lowercase hex characters to bytes.
fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// Adds the document's endorsements to `policy`, unions its revocations into
/// the revoked set, and records its version. Pins are left alone: revocation
/// takes precedence over them when a compose is checked.
pub fn merge(policy: &mut Policy, doc: &FeedDocument) {
    for &(role, m, hash) in &doc.entries {
        policy.endorsed.insert((m, hash), role);
    }
    policy.revoked.extend(doc.revoked.iter().copied());
    policy.feed_version = Some(doc.version);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{Match, Policy, Role};
    use crate::inference::NearEnvironment;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    const A64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B64: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C64: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    /// 2026-11-25T00:00:00Z.
    const ISSUED: u64 = 1_764_028_800;
    const DAY: u64 = 86_400;
    const KEY1_HEX: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const KEY2_HEX: &str = "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";

    fn ci() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }
    fn recovery() -> SigningKey {
        SigningKey::from_bytes(&[8; 32])
    }
    fn keys() -> Vec<[u8; 32]> {
        vec![
            ci().verifying_key().to_bytes(),
            recovery().verifying_key().to_bytes(),
        ]
    }
    fn sig(bytes: &[u8], k: &SigningKey) -> Vec<u8> {
        STANDARD.encode(k.sign(bytes).to_bytes()).into_bytes()
    }
    fn rfc3339(t: u64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp(t as i64, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    /// A document as CI would publish it, with one field overridable.
    struct Doc {
        schema: u64,
        environment: &'static str,
        version: u64,
        issued: u64,
        expires: u64,
        entries: String,
        revoked: String,
    }

    impl Doc {
        fn good() -> Doc {
            Doc {
                schema: 1,
                environment: "production",
                version: ISSUED,
                issued: ISSUED,
                expires: ISSUED + 3 * DAY,
                entries: format!(
                    r#"[
    {{"role": "gateway", "match": "exact", "sha256": "{A64}", "app_name": "dstack-0.5.12", "first_seen": "2026-11-23T17:02:11Z", "endorsed_by": "rules:gateway-v1"}},
    {{"role": "model", "match": "instance-label-v1", "sha256": "{B64}", "app_name": "dstack-nvidia-0.5.11", "first_seen": "2026-11-20T09:14:40Z", "endorsed_by": "rules:model-v1"}}
  ]"#
                ),
                revoked: format!(r#"["{C64}"]"#),
            }
        }
        fn text(&self) -> String {
            format!(
                "{{\n  \"schema\": {},\n  \"environment\": \"{}\",\n  \"version\": {},\n  \"issued\": \"{}\",\n  \"expires\": \"{}\",\n  \"entries\": {},\n  \"revoked\": {}\n}}\n",
                self.schema,
                self.environment,
                self.version,
                rfc3339(self.issued),
                rfc3339(self.expires),
                self.entries,
                self.revoked,
            )
        }
    }

    /// Signs `text` with the CI key and verifies it at `now`.
    fn check(text: &str, now: u64, high_water: u64) -> Result<FeedDocument, String> {
        verify_document(
            text.as_bytes(),
            &sig(text.as_bytes(), &ci()),
            &keys(),
            NearEnvironment::Production,
            now,
            high_water,
        )
    }

    fn hash(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_test_keys_are_the_fixed_seed_keys() {
        assert_eq!(hex::encode(ci().verifying_key().to_bytes()), KEY1_HEX);
        assert_eq!(hex::encode(recovery().verifying_key().to_bytes()), KEY2_HEX);
    }

    #[test]
    fn accepts_either_key() {
        let text = Doc::good().text();
        for k in [ci(), recovery()] {
            let d = verify_document(
                text.as_bytes(),
                &sig(text.as_bytes(), &k),
                &keys(),
                NearEnvironment::Production,
                ISSUED + 60,
                0,
            )
            .unwrap();
            assert_eq!(d.environment, NearEnvironment::Production);
            assert_eq!(
                (d.version, d.issued, d.expires),
                (ISSUED, ISSUED, ISSUED + 3 * DAY)
            );
            assert_eq!(
                d.entries,
                vec![
                    (Role::Gateway, Match::Exact, hash(A64)),
                    (Role::Model, Match::InstanceLabelV1, hash(B64)),
                ]
            );
            assert_eq!(d.revoked, BTreeSet::from([hash(C64)]));
        }
        // Either key alone is enough.
        let only_recovery = [recovery().verifying_key().to_bytes()];
        assert!(
            verify_document(
                text.as_bytes(),
                &sig(text.as_bytes(), &recovery()),
                &only_recovery,
                NearEnvironment::Production,
                ISSUED,
                0,
            )
            .is_ok()
        );
    }

    #[test]
    fn a_trailing_newline_on_the_signature_is_tolerated() {
        let text = Doc::good().text();
        let mut s = sig(text.as_bytes(), &ci());
        s.push(b'\n');
        assert!(
            verify_document(
                text.as_bytes(),
                &s,
                &keys(),
                NearEnvironment::Production,
                ISSUED,
                0
            )
            .is_ok()
        );
    }

    #[test]
    fn refuses_a_flipped_document_byte_and_a_flipped_signature_byte() {
        let text = Doc::good().text();
        let s = sig(text.as_bytes(), &ci());

        // Every byte of the document, so a flip that breaks the JSON still
        // reports the signature, never a parse error.
        for i in 0..text.len() {
            let mut doc = text.as_bytes().to_vec();
            doc[i] ^= 0x01;
            let e = verify_document(&doc, &s, &keys(), NearEnvironment::Production, ISSUED, 0)
                .unwrap_err();
            assert!(e.contains("signature"), "byte {i}: {e}");
        }

        let raw = STANDARD.decode(&s).unwrap();
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0x01;
            let bad = STANDARD.encode(&bad).into_bytes();
            let e = verify_document(
                text.as_bytes(),
                &bad,
                &keys(),
                NearEnvironment::Production,
                ISSUED,
                0,
            )
            .unwrap_err();
            assert!(e.contains("signature"), "byte {i}: {e}");
        }
    }

    #[test]
    fn refuses_malformed_signatures() {
        let text = Doc::good().text();
        for bad in [
            b"".to_vec(),
            b"not base64!".to_vec(),
            STANDARD.encode([0u8; 63]).into_bytes(),
            STANDARD.encode([0u8; 65]).into_bytes(),
            STANDARD.encode([0u8; 64]).into_bytes(),
        ] {
            let e = verify_document(
                text.as_bytes(),
                &bad,
                &keys(),
                NearEnvironment::Production,
                ISSUED,
                0,
            )
            .unwrap_err();
            assert!(e.contains("signature"), "{e}");
        }
    }

    /// The order of the Ed25519 group, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    #[test]
    fn refuses_a_non_canonical_signature() {
        let text = Doc::good().text();
        let raw = ci().sign(text.as_bytes()).to_bytes();
        // s + L: the same scalar mod L, which verify_strict refuses.
        let mut malleated = raw;
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(raw[32 + i]) + u16::from(L[i]) + carry;
            malleated[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L fits in 256 bits");
        assert_ne!(malleated, raw);
        let bad = STANDARD.encode(malleated).into_bytes();
        let e = verify_document(
            text.as_bytes(),
            &bad,
            &keys(),
            NearEnvironment::Production,
            ISSUED,
            0,
        )
        .unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn refuses_a_document_signed_by_another_key() {
        let text = Doc::good().text();
        // Stands in for the update key: a valid key that is not a feed key.
        let other = SigningKey::from_bytes(&[9; 32]);
        let e = verify_document(
            text.as_bytes(),
            &sig(text.as_bytes(), &other),
            &keys(),
            NearEnvironment::Production,
            ISSUED,
            0,
        )
        .unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn refuses_when_no_key_is_compiled_in() {
        let text = Doc::good().text();
        let e = verify_document(
            text.as_bytes(),
            &sig(text.as_bytes(), &ci()),
            &[],
            NearEnvironment::Production,
            ISSUED,
            0,
        )
        .unwrap_err();
        assert!(e.contains("key"), "{e}");
    }

    #[test]
    fn an_invalid_compiled_in_key_is_skipped() {
        // Not a point on the curve: y = 2 has no x.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&not_a_point).is_err());
        let text = Doc::good().text();
        let keys = [not_a_point, ci().verifying_key().to_bytes()];
        assert!(
            verify_document(
                text.as_bytes(),
                &sig(text.as_bytes(), &ci()),
                &keys,
                NearEnvironment::Production,
                ISSUED,
                0,
            )
            .is_ok()
        );
    }

    #[test]
    fn refuses_the_other_environment() {
        let staging = Doc {
            environment: "staging",
            ..Doc::good()
        }
        .text();
        let e = check(&staging, ISSUED, 0).unwrap_err();
        assert!(e.contains("environment"), "{e}");
        // The same document is accepted for staging.
        let d = verify_document(
            staging.as_bytes(),
            &sig(staging.as_bytes(), &ci()),
            &keys(),
            NearEnvironment::Staging,
            ISSUED,
            0,
        )
        .unwrap();
        assert_eq!(d.environment, NearEnvironment::Staging);

        let unknown = Doc {
            environment: "Production",
            ..Doc::good()
        }
        .text();
        let e = check(&unknown, ISSUED, 0).unwrap_err();
        assert!(e.contains("environment"), "{e}");
    }

    #[test]
    fn refuses_a_schema_other_than_1() {
        for schema in [0, 2] {
            let e = check(
                &Doc {
                    schema,
                    ..Doc::good()
                }
                .text(),
                ISSUED,
                0,
            )
            .unwrap_err();
            assert!(e.contains("schema"), "{e}");
        }
    }

    #[test]
    fn refuses_an_expired_document() {
        let text = Doc::good().text();
        let expires = ISSUED + 3 * DAY;
        assert!(check(&text, expires - 1, 0).is_ok());
        let e = check(&text, expires, 0).unwrap_err();
        assert!(e.contains("expired"), "{e}");
        assert!(check(&text, expires + DAY, 0).is_err());
    }

    #[test]
    fn accepts_issued_up_to_300s_ahead_and_refuses_301s() {
        let text = Doc::good().text();
        assert!(check(&text, ISSUED - 300, 0).is_ok());
        let e = check(&text, ISSUED - 301, 0).unwrap_err();
        assert!(e.contains("future"), "{e}");
    }

    #[test]
    fn refuses_a_window_over_7_days() {
        let seven = Doc {
            expires: ISSUED + 7 * DAY,
            ..Doc::good()
        }
        .text();
        assert!(check(&seven, ISSUED, 0).is_ok());
        let over = Doc {
            expires: ISSUED + 7 * DAY + 1,
            ..Doc::good()
        }
        .text();
        let e = check(&over, ISSUED, 0).unwrap_err();
        assert!(e.contains("7 days"), "{e}");
    }

    #[test]
    fn refuses_expires_before_issued() {
        let text = Doc {
            expires: ISSUED - 1,
            ..Doc::good()
        }
        .text();
        assert!(check(&text, ISSUED - 10, 0).is_err());
        let same = Doc {
            expires: ISSUED,
            ..Doc::good()
        }
        .text();
        assert!(check(&same, ISSUED - 10, 0).is_err());
    }

    #[test]
    fn refuses_a_time_before_1970() {
        let text = Doc::good()
            .text()
            .replace(&rfc3339(ISSUED), "1969-12-31T23:59:59Z");
        assert!(check(&text, ISSUED, 0).is_err());
    }

    #[test]
    fn refuses_a_version_below_the_high_water_and_accepts_equal() {
        let text = Doc::good().text();
        assert!(check(&text, ISSUED, ISSUED - 1).is_ok());
        assert!(check(&text, ISSUED, ISSUED).is_ok());
        let e = check(&text, ISSUED, ISSUED + 1).unwrap_err();
        assert!(e.contains("version"), "{e}");
    }

    #[test]
    fn skips_an_unknown_match_and_refuses_an_unknown_role() {
        let entries = format!(
            r#"[{{"role": "model", "match": "instance-label-v2", "sha256": "{A64}"}}, {{"role": "gateway", "match": "exact", "sha256": "{B64}"}}]"#
        );
        let d = check(
            &Doc {
                entries,
                ..Doc::good()
            }
            .text(),
            ISSUED,
            0,
        )
        .unwrap();
        assert_eq!(d.entries, vec![(Role::Gateway, Match::Exact, hash(B64))]);

        for role in ["router", "Model", ""] {
            let entries = format!(r#"[{{"role": "{role}", "match": "exact", "sha256": "{A64}"}}]"#);
            assert!(
                check(
                    &Doc {
                        entries,
                        ..Doc::good()
                    }
                    .text(),
                    ISSUED,
                    0
                )
                .is_err(),
                "{role}"
            );
        }
        // An unknown role is refused even on an entry whose match is skipped.
        let entries =
            format!(r#"[{{"role": "router", "match": "instance-label-v2", "sha256": "{A64}"}}]"#);
        assert!(
            check(
                &Doc {
                    entries,
                    ..Doc::good()
                }
                .text(),
                ISSUED,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_a_malformed_sha256() {
        for bad in [
            A64.to_uppercase(),
            A64[1..].to_string(),
            format!("{A64}a"),
            format!("{}g", &A64[1..]),
        ] {
            let entries = format!(r#"[{{"role": "model", "match": "exact", "sha256": "{bad}"}}]"#);
            let e = check(
                &Doc {
                    entries,
                    ..Doc::good()
                }
                .text(),
                ISSUED,
                0,
            )
            .unwrap_err();
            assert!(e.contains("sha256"), "{bad}: {e}");

            // Also on an entry whose match is skipped.
            let entries = format!(
                r#"[{{"role": "model", "match": "instance-label-v2", "sha256": "{bad}"}}]"#
            );
            let e = check(
                &Doc {
                    entries,
                    ..Doc::good()
                }
                .text(),
                ISSUED,
                0,
            )
            .unwrap_err();
            assert!(e.contains("sha256"), "{bad}: {e}");

            let revoked = format!(r#"["{bad}"]"#);
            let e = check(
                &Doc {
                    revoked,
                    ..Doc::good()
                }
                .text(),
                ISSUED,
                0,
            )
            .unwrap_err();
            assert!(e.contains("sha256"), "{bad}: {e}");
        }
    }

    #[test]
    fn refuses_one_hash_under_two_roles() {
        let entries = format!(
            r#"[{{"role": "model", "match": "exact", "sha256": "{A64}"}}, {{"role": "gateway", "match": "exact", "sha256": "{A64}"}}]"#
        );
        let e = check(
            &Doc {
                entries,
                ..Doc::good()
            }
            .text(),
            ISSUED,
            0,
        )
        .unwrap_err();
        assert!(e.contains("two roles"), "{e}");

        // The same hash under two match types, or twice under one role, is fine.
        let entries = format!(
            r#"[{{"role": "model", "match": "exact", "sha256": "{A64}"}}, {{"role": "model", "match": "instance-label-v1", "sha256": "{A64}"}}, {{"role": "model", "match": "exact", "sha256": "{A64}"}}]"#
        );
        assert!(
            check(
                &Doc {
                    entries,
                    ..Doc::good()
                }
                .text(),
                ISSUED,
                0
            )
            .is_ok()
        );
    }

    #[test]
    fn refuses_signed_but_malformed_documents() {
        let good = Doc::good().text();
        for text in [
            "not JSON".to_string(),
            good.replace("\"revoked\"", "\"revoked_hashes\""),
            good.replace(&rfc3339(ISSUED), "yesterday"),
            good.replace(&format!("\"version\": {ISSUED}"), "\"version\": -1"),
            good.replace(
                &format!("\"version\": {ISSUED}"),
                &format!("\"version\": {ISSUED}, \"version\": {ISSUED}"),
            ),
        ] {
            assert_ne!(text, good);
            let e = check(&text, ISSUED, 0).unwrap_err();
            assert!(!e.contains("signature"), "{e}");
        }
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let text = Doc::good()
            .text()
            .replacen("{\n", "{\n  \"publisher\": \"ci\",\n", 1);
        assert!(check(&text, ISSUED, 0).is_ok());
    }

    #[test]
    fn merge_adds_endorsements_unions_revocations_and_sets_the_version() {
        let d = check(&Doc::good().text(), ISSUED, 0).unwrap();
        let mut policy = Policy::default();
        policy.pinned.insert(hash(C64), Role::Model);
        let earlier = hash("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        policy.revoked.insert(earlier);

        merge(&mut policy, &d);

        assert_eq!(policy.pinned, [(hash(C64), Role::Model)].into());
        assert_eq!(
            policy.endorsed,
            [
                ((Match::Exact, hash(A64)), Role::Gateway),
                ((Match::InstanceLabelV1, hash(B64)), Role::Model),
            ]
            .into()
        );
        assert_eq!(policy.revoked, BTreeSet::from([earlier, hash(C64)]));
        assert_eq!(policy.feed_version, Some(ISSUED));
    }

    #[test]
    fn parse_feed_keys_reads_one_or_two() {
        let (k, n) = parse_feed_keys(KEY1_HEX);
        assert_eq!((n, k[0]), (1, hash(KEY1_HEX)));
        let both = format!("{KEY1_HEX},{}", KEY2_HEX.to_uppercase());
        let (k, n) = parse_feed_keys(&both);
        assert_eq!((n, k[0], k[1]), (2, hash(KEY1_HEX), hash(KEY2_HEX)));
    }

    #[test]
    #[should_panic(expected = "RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX")]
    fn parse_feed_keys_reads_one_or_two_and_panics_on_three() {
        parse_feed_keys(&format!("{KEY1_HEX},{KEY2_HEX},{KEY1_HEX}"));
    }

    #[test]
    fn parse_feed_keys_panics_on_malformed_values() {
        for bad in [
            String::new(),
            format!("{KEY1_HEX},"),
            format!(",{KEY1_HEX}"),
            format!("{KEY1_HEX}, {KEY2_HEX}"),
            KEY1_HEX[1..].to_string(),
            format!("{KEY1_HEX}0"),
            format!("{}g", &KEY1_HEX[1..]),
        ] {
            let e = std::panic::catch_unwind(|| parse_feed_keys(&bad)).unwrap_err();
            let msg = e.downcast_ref::<&str>().copied().unwrap_or_default();
            assert!(
                msg.contains("RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX"),
                "{bad:?}: {msg}"
            );
        }
    }

    #[test]
    fn a_build_without_the_variable_has_no_feed_keys() {
        if option_env!("RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX").is_none() {
            assert!(FEED_KEYS.is_empty());
        } else {
            assert!(matches!(FEED_KEYS.len(), 1 | 2));
        }
    }
}
