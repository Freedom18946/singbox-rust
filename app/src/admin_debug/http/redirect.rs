// SPDX-License-Identifier: Apache-2.0
use reqwest::redirect::{Action, Attempt};
use url::Url;

#[derive(Clone)]
pub struct SafeRedirect {
    // Allow list/policy can be read from global config, interface left here
    allow_host_suffix: Vec<String>,
}

impl SafeRedirect {
    pub fn new(allow_host_suffix: Vec<String>) -> Self { Self { allow_host_suffix } }

    fn host_allowed(&self, host: &str) -> bool {
        self.allow_host_suffix.iter().any(|suf| host.ends_with(suf))
    }

    fn forbid_private_or_loopback(host: &str) -> bool {
        // Rough filtering: localhost/private network segment keywords directly refuse
        let h = host.to_ascii_lowercase();
        !(h == "localhost" || h.ends_with(".local") || h.starts_with("127.") || h.starts_with("10.")
          || h.starts_with("172.16.") || h.starts_with("192.168.") || h.starts_with("169.254."))
    }

    pub fn policy(self) -> impl Fn(Attempt) -> Action + Clone + Send + Sync + 'static {
        move |att: Attempt| {
            let url: &Url = att.url();
            let host = url.host_str().unwrap_or_default();
            if !Self::forbid_private_or_loopback(host) { return att.stop(); }
            if !self.host_allowed(host) { return att.stop(); }
            if att.previous().len() > 10 { return att.stop(); } // Prevent redirect bombing
            att.follow()
        }
    }
}