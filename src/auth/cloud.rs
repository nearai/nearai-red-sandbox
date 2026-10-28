use super::{HostSecret, InferenceCredential, LoginOptions, Provider, choose, valid_id, valid_key};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::io::Read;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const ORIGIN: &str = "https://cloud-api.near.ai";
const MAX_RESPONSE: u64 = 256 * 1024;

pub(super) struct CloudApi {
    origin: url::Url,
    http: reqwest::blocking::Client,
    deadline: Instant,
}

#[derive(Deserialize)]
struct Choice {
    id: String,
    is_active: bool,
}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    organizations: Option<Vec<Choice>>,
    #[serde(default)]
    workspaces: Option<Vec<Choice>>,
    total: usize,
    offset: usize,
}

#[derive(Deserialize)]
struct Minted {
    id: String,
    workspace_id: String,
    key: String,
}

impl Drop for Minted {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl CloudApi {
    pub(super) fn live(deadline: Instant) -> Result<Self, String> {
        Self::build(ORIGIN, deadline)
    }

    fn build(origin: &str, deadline: Instant) -> Result<Self, String> {
        Ok(Self {
            origin: url::Url::parse(origin).map_err(|_| "Invalid NEAR AI service origin")?,
            http: reqwest::blocking::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .user_agent("nearai-red-sandbox/0.1")
                .build()
                .map_err(|_| "Cannot create NEAR AI Cloud client")?,
            deadline,
        })
    }

    #[cfg(test)]
    pub(super) fn for_test(origin: &str, deadline: Instant) -> Self {
        let parsed = url::Url::parse(origin).unwrap();
        assert_eq!(parsed.scheme(), "http");
        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        Self::build(origin, deadline).unwrap()
    }

    pub(super) fn authorize_url(
        &self,
        provider: Provider,
        callback: &str,
    ) -> Result<String, String> {
        let parsed = url::Url::parse(callback).map_err(|_| "Invalid NEAR AI callback")?;
        if parsed.scheme() != "http"
            || parsed.host_str() != Some("127.0.0.1")
            || parsed.port().is_none_or(|port| port == 0)
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err("Invalid NEAR AI callback".into());
        }
        let provider = match provider {
            Provider::Github => "github",
            Provider::Google => "google",
        };
        let mut url = self
            .origin
            .join(&format!("/v1/auth/{provider}"))
            .map_err(|_| "Invalid NEAR AI authorization URL")?;
        url.query_pairs_mut()
            .append_pair("frontend_callback", callback);
        Ok(url.into())
    }

    pub(super) fn mint(
        &self,
        session: &HostSecret,
        options: &LoginOptions,
    ) -> Result<InferenceCredential, String> {
        let organizations = self.list("/v1/organizations", session, true)?;
        let organization_id = choose(
            &organizations,
            options.organization.as_deref(),
            "organization",
        )?;
        let workspaces = self.list(
            &format!("/v1/organizations/{organization_id}/workspaces"),
            session,
            false,
        )?;
        let workspace_id = choose(&workspaces, options.workspace.as_deref(), "workspace")?;
        let mut minted: Minted = self.call(reqwest::Method::POST, &format!("/v1/workspaces/{workspace_id}/api-keys"), session,
            Some(&serde_json::json!({"name": format!("nearai-red-sandbox-{}", crate::protocol::random_hex(12))})))?;
        if !valid_id(&minted.id) || minted.workspace_id != workspace_id || !valid_key(&minted.key) {
            return Err("NEAR AI Cloud returned an invalid inference credential".into());
        }
        Ok(InferenceCredential {
            key: std::mem::take(&mut minted.key).into(),
            key_id: std::mem::take(&mut minted.id),
            organization_id,
            workspace_id,
        })
    }

    fn list(
        &self,
        path: &str,
        session: &HostSecret,
        organizations: bool,
    ) -> Result<Vec<String>, String> {
        let mut offset = 0;
        let mut result = Vec::new();
        // A bounded full list is needed before a sole account can be implicit.
        // Refuse inconsistent/changing pagination rather than guess an account.
        loop {
            let page: Page = self.call(
                reqwest::Method::GET,
                &format!("{path}?limit=100&offset={offset}"),
                session,
                None,
            )?;
            let choices = if organizations {
                page.organizations
            } else {
                page.workspaces
            }
            .ok_or("NEAR AI Cloud returned an invalid account list")?;
            if page.offset != offset
                || page.total > 1000
                || choices.len() > 100
                || (choices.is_empty() && offset < page.total)
            {
                return Err("NEAR AI Cloud account list is incomplete; choose an account at https://cloud.near.ai".into());
            }
            offset += choices.len();
            for item in choices {
                if !valid_id(&item.id) {
                    return Err("NEAR AI Cloud returned an invalid account ID".into());
                }
                if item.is_active {
                    if result.contains(&item.id) {
                        return Err("NEAR AI Cloud account list changed; retry sign-in".into());
                    }
                    result.push(item.id);
                }
            }
            if offset >= page.total {
                return Ok(result);
            }
        }
    }

    fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        session: &HostSecret,
        body: Option<&serde_json::Value>,
    ) -> Result<T, String> {
        super::browser::check_deadline(self.deadline, &|| crate::sys::take_signal().is_some())?;
        let url = self
            .origin
            .join(path)
            .map_err(|_| "Invalid NEAR AI Cloud path")?;
        if url.origin() != self.origin.origin() {
            return Err("NEAR AI Cloud destination refused".into());
        }
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(session.expose_secret())
            .timeout(
                self.deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(30)),
            );
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|_| "NEAR AI Cloud request failed; retry sign-in")?;
        if !response.status().is_success() {
            return Err(if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                "NEAR AI session expired; retry sign-in"
            } else {
                "NEAR AI Cloud refused account setup"
            }
            .into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read NEAR AI Cloud response")?;
        if bytes.len() as u64 > MAX_RESPONSE {
            return Err("NEAR AI Cloud response exceeded its limit".into());
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| "NEAR AI Cloud returned an unexpected response".into())
    }
}
