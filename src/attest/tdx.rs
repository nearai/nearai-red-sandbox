//! TDX quote verification with `dcap-qvl` over collateral fetched from Intel
//! PCS. Every failure is an `Err`; the caller refuses.

use std::sync::Arc;

use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::quote::Quote;
use serde::Deserialize;
use serde_json::value::RawValue;

use super::http::{Http, HttpResponse};

pub const INTEL_PCS: &str = "https://api.trustedservices.intel.com";
pub const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// Certification data type 5: the PCK certificate chain, PEM, in the quote.
const PCK_CERT_CHAIN: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcsUrls {
    pub pck_crl: String,
    pub tcb_info: String,
    pub qe_identity: String,
    pub root_ca_crl: String,
}

/// The PCS v4 collateral URLs for a TDX platform, as `dcap-qvl` 0.7.0
/// builds them against PCS with the standard TCB evaluation data set.
pub fn pcs_urls(fmspc: &[u8; 6], ca: &str) -> PcsUrls {
    PcsUrls {
        pck_crl: format!("{INTEL_PCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"),
        tcb_info: format!(
            "{INTEL_PCS}/tdx/certification/v4/tcb?fmspc={}&update=standard",
            hex::encode_upper(fmspc)
        ),
        qe_identity: format!("{INTEL_PCS}/tdx/certification/v4/qe/identity?update=standard"),
        root_ca_crl: INTEL_ROOT_CA_CRL_URL.to_string(),
    }
}

/// Decodes `%XX` escapes. `+` stays `+`; a malformed escape or a result that
/// is not UTF-8 refuses.
pub fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .ok_or("malformed percent escape")?;
            let hex = std::str::from_utf8(hex).map_err(|_| "malformed percent escape")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "malformed percent escape")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "percent-decoded value is not UTF-8".to_string())
}

fn parse_tdx(quote: &[u8]) -> Result<Quote, String> {
    let q = Quote::parse(quote).map_err(|e| format!("cannot parse quote: {e:#}"))?;
    if q.report.as_td10().is_none() {
        return Err("not a TDX quote".to_string());
    }
    Ok(q)
}

fn get_ok(http: &dyn Http, url: &str) -> Result<HttpResponse, String> {
    let r = http.get(url, None)?;
    if !(200..300).contains(&r.status) {
        return Err(format!("{url}: HTTP {}", r.status));
    }
    Ok(r)
}

fn issuer_chain(r: &HttpResponse, url: &str, names: &[&str]) -> Result<String, String> {
    let value = names
        .iter()
        .find_map(|n| r.header(n))
        .ok_or_else(|| format!("{url}: missing {} header", names[0]))?;
    percent_decode(value).map_err(|e| format!("{url}: {} header: {e}", names[0]))
}

#[derive(Deserialize)]
struct TcbInfoResponse<'a> {
    #[serde(rename = "tcbInfo", borrow)]
    tcb_info: &'a RawValue,
    signature: String,
}

#[derive(Deserialize)]
struct QeIdentityResponse<'a> {
    #[serde(rename = "enclaveIdentity", borrow)]
    enclave_identity: &'a RawValue,
    signature: String,
}

fn signature(hex_sig: &str, url: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_sig).map_err(|_| format!("{url}: signature is not hex"))
}

/// Fetches the collateral for a TDX quote from Intel PCS. `tcb_info` and
/// `qe_identity` are the exact bytes Intel signed.
pub fn fetch_collateral(http: &dyn Http, quote: &[u8]) -> Result<QuoteCollateralV3, String> {
    let q = parse_tdx(quote)?;
    let cert_type = q.inner_cert_type();
    if cert_type != PCK_CERT_CHAIN {
        return Err(format!(
            "unsupported PCK certification data type {cert_type}"
        ));
    }
    let pck_chain = String::from_utf8(q.inner_cert_data().to_vec())
        .map_err(|_| "PCK certificate chain in the quote is not UTF-8".to_string())?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&q).map_err(|e| format!("quote FMSPC: {e:#}"))?;
    let ca = dcap_qvl::intel::quote_ca(&q).map_err(|e| format!("quote PCK CA: {e:#}"))?;
    let u = pcs_urls(&fmspc, ca.as_id_str());

    let r = get_ok(http, &u.pck_crl)?;
    let pck_crl_issuer_chain = issuer_chain(&r, &u.pck_crl, &["SGX-PCK-CRL-Issuer-Chain"])?;
    let pck_crl = r.body;

    let r = get_ok(http, &u.tcb_info)?;
    let tcb_info_issuer_chain = issuer_chain(
        &r,
        &u.tcb_info,
        &["TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"],
    )?;
    let tcb: TcbInfoResponse =
        serde_json::from_slice(&r.body).map_err(|e| format!("{}: {e}", u.tcb_info))?;
    let tcb_info = tcb.tcb_info.get().to_string();
    let tcb_info_signature = signature(&tcb.signature, &u.tcb_info)?;

    let r = get_ok(http, &u.qe_identity)?;
    let qe_identity_issuer_chain =
        issuer_chain(&r, &u.qe_identity, &["SGX-Enclave-Identity-Issuer-Chain"])?;
    let qe: QeIdentityResponse =
        serde_json::from_slice(&r.body).map_err(|e| format!("{}: {e}", u.qe_identity))?;
    let qe_identity = qe.enclave_identity.get().to_string();
    let qe_identity_signature = signature(&qe.signature, &u.qe_identity)?;

    let root_ca_crl = get_ok(http, &u.root_ca_crl)?.body;

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: Some(pck_chain),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxClaims {
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    pub report_data: [u8; 64],
    pub mr_config_id: [u8; 48],
}

/// Verifies a TDX quote against its collateral at `now_unix`: the PCK chain
/// to Intel's root, the CRLs, the TCB info and QE identity signatures, the QE
/// report, and the quote signature. Does not apply a TCB policy.
pub fn verify_quote(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_unix: u64,
) -> Result<TdxClaims, String> {
    parse_tdx(quote)?;
    let v = dcap_qvl::verify::ring::verify(quote, collateral, now_unix)
        .map_err(|e| format!("TDX quote verification failed: {e:#}"))?;
    let td = v
        .report
        .as_td10()
        .ok_or_else(|| "not a TDX quote".to_string())?;
    Ok(TdxClaims {
        tcb_status: v.status,
        advisory_ids: v.advisory_ids,
        report_data: td.report_data,
        mr_config_id: td.mr_config_id,
    })
}

pub trait QuoteVerifier: Send + Sync {
    fn verify(&self, quote: &[u8], now_unix: u64) -> Result<TdxClaims, String>;
}

pub struct PcsQuoteVerifier {
    pub http: Arc<dyn Http>,
}

impl QuoteVerifier for PcsQuoteVerifier {
    fn verify(&self, quote: &[u8], now_unix: u64) -> Result<TdxClaims, String> {
        let collateral = fetch_collateral(self.http.as_ref(), quote)?;
        verify_quote(quote, &collateral, now_unix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TcbAcceptance {
    UpToDate,
    OutOfDateAllowed,
}

/// Accepts `UpToDate`, and `OutOfDate` only when explicitly allowed. Every
/// other status, known or not, refuses.
pub fn tcb_policy(status: &str, allow_out_of_date: bool) -> Result<TcbAcceptance, String> {
    match status {
        "UpToDate" => Ok(TcbAcceptance::UpToDate),
        "OutOfDate" if allow_out_of_date => Ok(TcbAcceptance::OutOfDateAllowed),
        "OutOfDate" => Err(
            "TDX TCB status is OutOfDate; pass --allow-tcb-out-of-date to accept it".to_string(),
        ),
        other => Err(format!("TDX TCB status {other:?} is not accepted")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::http::{FakeHttp, Http, HttpResponse};
    use dcap_qvl::QuoteCollateralV3;

    const QUOTE: &[u8] = include_bytes!("../../tests/fixtures/dcap/tdx_quote");
    const COLLATERAL: &str = include_str!("../../tests/fixtures/dcap/tdx_quote_collateral.json");
    const SGX_QUOTE: &[u8] = include_bytes!("../../vendor/dcap-qvl-0.7.0/sample/sgx_quote");
    const NOW: u64 = 1_751_328_000; // 2025-07-01T00:00:00Z, inside the window
    const LATE: u64 = 1_753_000_000; // 2025-07-20T08:26:40Z, after the PCK CRL's nextUpdate
    // TD report body starts at byte 48; report_data is at body offset 520
    // (16 + 48 + 48 + 8 + 8 + 8 + 48 + 48 + 48 + 48 + 4 * 48).
    const REPORT_DATA_AT: usize = 48 + 520;

    fn sample() -> QuoteCollateralV3 {
        serde_json::from_str(COLLATERAL).unwrap()
    }

    /// %XX for every byte outside A-Za-z0-9-._~ (the inverse of percent_decode).
    fn pct(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    fn ok(headers: Vec<(&str, String)>, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: headers.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            body,
        }
    }

    fn tcb_body(c: &QuoteCollateralV3) -> Vec<u8> {
        format!(
            r#"{{"tcbInfo":{},"signature":"{}"}}"#,
            c.tcb_info,
            hex::encode(&c.tcb_info_signature)
        )
        .into_bytes()
    }

    /// Routes every PCS URL for the sample quote; returns the URLs.
    fn route_sample(http: &FakeHttp, c: &QuoteCollateralV3) -> PcsUrls {
        let u = pcs_urls(b"\xB0\xC0\x6F\x00\x00\x00", "platform");
        http.route(
            "GET",
            &u.pck_crl,
            ok(
                vec![("SGX-PCK-CRL-Issuer-Chain", pct(&c.pck_crl_issuer_chain))],
                c.pck_crl.clone(),
            ),
        );
        http.route(
            "GET",
            &u.tcb_info,
            ok(
                vec![("TCB-Info-Issuer-Chain", pct(&c.tcb_info_issuer_chain))],
                tcb_body(c),
            ),
        );
        http.route(
            "GET",
            &u.qe_identity,
            ok(
                vec![(
                    "SGX-Enclave-Identity-Issuer-Chain",
                    pct(&c.qe_identity_issuer_chain),
                )],
                format!(
                    r#"{{"enclaveIdentity":{},"signature":"{}"}}"#,
                    c.qe_identity,
                    hex::encode(&c.qe_identity_signature)
                )
                .into_bytes(),
            ),
        );
        http.route("GET", &u.root_ca_crl, ok(vec![], c.root_ca_crl.clone()));
        u
    }

    #[test]
    fn the_sample_quote_verifies_up_to_date_at_a_fixed_time() {
        let c = verify_quote(QUOTE, &sample(), NOW).unwrap();
        assert_eq!(c.tcb_status, "UpToDate");
        assert!(c.advisory_ids.is_empty());
        let q = dcap_qvl::quote::Quote::parse(QUOTE).unwrap();
        let td = q.report.as_td10().unwrap();
        assert_eq!(c.report_data, td.report_data);
        assert_eq!(c.mr_config_id, td.mr_config_id);
        // The offset used by the tamper test really is report_data.
        assert_eq!(
            &QUOTE[REPORT_DATA_AT..REPORT_DATA_AT + 64],
            &td.report_data[..]
        );
    }

    #[test]
    fn a_one_byte_flip_in_report_data_is_refused() {
        let mut q = QUOTE.to_vec();
        q[REPORT_DATA_AT] ^= 0x01;
        assert!(verify_quote(&q, &sample(), NOW).is_err());
    }

    #[test]
    fn tampered_collateral_and_a_late_clock_are_refused() {
        let mut c = sample();
        c.tcb_info = c.tcb_info.replacen("\"TDX\"", "\"TDY\"", 1);
        assert_ne!(c.tcb_info, sample().tcb_info);
        assert!(verify_quote(QUOTE, &c, NOW).is_err());
        assert!(verify_quote(QUOTE, &sample(), LATE).is_err());
    }

    #[test]
    fn the_window_edges_are_enforced_including_the_pck_crl_next_update() {
        // QE identity issueDate 2025-06-19T10:32:27Z opens the window.
        assert!(verify_quote(QUOTE, &sample(), 1_750_329_146).is_err());
        assert!(verify_quote(QUOTE, &sample(), 1_750_329_147).is_ok());
        // PCK CRL nextUpdate 2025-07-19T10:00:35Z closes it (webpki counts
        // that second as expired), before TCB info and QE identity expire.
        assert!(verify_quote(QUOTE, &sample(), 1_752_919_234).is_ok());
        let e = verify_quote(QUOTE, &sample(), 1_752_919_235).unwrap_err();
        assert!(e.contains("CrlExpired"), "{e}");
    }

    #[test]
    fn an_sgx_quote_is_refused() {
        let e = verify_quote(SGX_QUOTE, &sample(), NOW).unwrap_err();
        assert!(e.contains("not a TDX quote"), "{e}");
        let http = FakeHttp::new();
        let e = fetch_collateral(http.as_ref(), SGX_QUOTE).unwrap_err();
        assert!(e.contains("not a TDX quote"), "{e}");
        assert!(http.calls().is_empty());
    }

    #[test]
    fn only_up_to_date_passes_unless_out_of_date_is_allowed() {
        assert_eq!(
            tcb_policy("UpToDate", false).unwrap(),
            TcbAcceptance::UpToDate
        );
        assert_eq!(
            tcb_policy("UpToDate", true).unwrap(),
            TcbAcceptance::UpToDate
        );
        assert!(
            tcb_policy("OutOfDate", false)
                .unwrap_err()
                .contains("--allow-tcb-out-of-date")
        );
        assert_eq!(
            tcb_policy("OutOfDate", true).unwrap(),
            TcbAcceptance::OutOfDateAllowed
        );
        for s in [
            "ConfigurationNeeded",
            "OutOfDateConfigurationNeeded",
            "SWHardeningNeeded",
            "ConfigurationAndSWHardeningNeeded",
            "Revoked",
            "TDRelaunchAdvised",
            "",
            "uptodate",
        ] {
            assert!(tcb_policy(s, true).is_err(), "{s}");
        }
    }

    #[test]
    fn collateral_comes_from_intel_pcs_and_verifies_the_sample() {
        let c = sample();
        let http = FakeHttp::new();
        let u = pcs_urls(b"\xB0\xC0\x6F\x00\x00\x00", "platform");
        assert_eq!(
            u.pck_crl,
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
        );
        assert_eq!(
            u.tcb_info,
            "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=B0C06F000000&update=standard"
        );
        assert_eq!(
            u.qe_identity,
            "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=standard"
        );
        assert_eq!(u.root_ca_crl, INTEL_ROOT_CA_CRL_URL);
        route_sample(&http, &c);
        let fetched = fetch_collateral(http.as_ref(), QUOTE).unwrap();
        assert_eq!(
            http.calls(),
            [u.pck_crl, u.tcb_info, u.qe_identity, u.root_ca_crl].map(|x| format!("GET {x}"))
        );
        assert_eq!(http.bearers(), [false; 4]);
        assert_eq!(fetched.tcb_info, c.tcb_info); // byte-exact
        assert_eq!(fetched.qe_identity, c.qe_identity);
        assert_eq!(fetched.tcb_info_signature, c.tcb_info_signature);
        assert_eq!(fetched.pck_crl_issuer_chain, c.pck_crl_issuer_chain);
        assert_eq!(fetched.tcb_info_issuer_chain, c.tcb_info_issuer_chain);
        assert_eq!(fetched.qe_identity_issuer_chain, c.qe_identity_issuer_chain);
        assert_eq!(fetched.pck_crl, c.pck_crl);
        assert_eq!(fetched.root_ca_crl, c.root_ca_crl);
        assert!(fetched.pck_certificate_chain.is_some());
        assert_eq!(
            verify_quote(QUOTE, &fetched, NOW).unwrap().tcb_status,
            "UpToDate"
        );
    }

    #[test]
    fn the_sgx_prefixed_tcb_issuer_header_is_accepted() {
        let c = sample();
        let http = FakeHttp::new();
        let u = route_sample(&http, &c);
        http.route(
            "GET",
            &u.tcb_info,
            ok(
                vec![("sgx-tcb-info-issuer-chain", pct(&c.tcb_info_issuer_chain))],
                tcb_body(&c),
            ),
        );
        let fetched = fetch_collateral(http.as_ref(), QUOTE).unwrap();
        assert_eq!(fetched.tcb_info_issuer_chain, c.tcb_info_issuer_chain);
    }

    #[test]
    fn a_pcs_error_or_a_missing_issuer_chain_is_refused() {
        let c = sample();

        let http = FakeHttp::new();
        let u = route_sample(&http, &c);
        http.route(
            "GET",
            &u.tcb_info,
            HttpResponse {
                status: 500,
                headers: vec![],
                body: vec![],
            },
        );
        let e = fetch_collateral(http.as_ref(), QUOTE).unwrap_err();
        assert!(e.contains(&u.tcb_info), "{e}");

        let http = FakeHttp::new();
        let u = route_sample(&http, &c);
        http.route("GET", &u.tcb_info, ok(vec![], tcb_body(&c)));
        let e = fetch_collateral(http.as_ref(), QUOTE).unwrap_err();
        assert!(e.contains("TCB-Info-Issuer-Chain"), "{e}");

        let http = FakeHttp::new();
        let u = route_sample(&http, &c);
        http.route(
            "GET",
            &u.tcb_info,
            ok(
                vec![("TCB-Info-Issuer-Chain", pct(&c.tcb_info_issuer_chain))],
                br#"{"signature":"00"}"#.to_vec(),
            ),
        );
        assert!(fetch_collateral(http.as_ref(), QUOTE).is_err());
    }

    #[test]
    fn a_pcs_quote_verifier_fetches_then_verifies() {
        let c = sample();
        let http = FakeHttp::new();
        route_sample(&http, &c);
        let v = PcsQuoteVerifier { http: http.clone() };
        assert_eq!(v.verify(QUOTE, NOW).unwrap().tcb_status, "UpToDate");
        assert!(v.verify(QUOTE, LATE).is_err());
    }

    #[test]
    fn percent_decoding_keeps_plus_and_refuses_bad_escapes() {
        assert_eq!(percent_decode("a%2Bb+c%0A").unwrap(), "a+b+c\n");
        assert_eq!(percent_decode("%2b%2B").unwrap(), "++");
        for bad in ["%", "%2", "%G0", "%FF", "%+1", "%-1"] {
            assert!(percent_decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fake_http_refuses_unrouted_calls_and_records_them() {
        let http = FakeHttp::new();
        let e = http.post_json("https://x.test/a", b"{}").unwrap_err();
        assert_eq!(e, "no route: POST https://x.test/a");
        assert_eq!(http.calls(), ["POST https://x.test/a"]);
        assert_eq!(http.bodies(), [b"{}".to_vec()]);
        let r = HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "x".into())],
            body: vec![],
        };
        assert_eq!(r.header("content-type"), Some("x"));
        assert_eq!(r.header("missing"), None);
    }
}
