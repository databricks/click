// Copyright 2017 Databricks, Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Code to handle reading and representing .kube/config files.

use chrono::{DateTime, Local, TimeZone};
use rustls::{Certificate, PrivateKey};
use serde_json::{self, Value};

use std::cell::RefCell;
use std::fs::File;
use std::io::Read;

use crate::error::KubeError;

// During testing we use a mock clock to be time independent.
#[cfg(test)]
use crate::duct_mock::cmd as ductcmd;
#[cfg(not(test))]
use duct::cmd as ductcmd;

/// Kubernetes cluster config
#[derive(Debug, Deserialize)]
pub struct Config {
    pub clusters: Vec<Cluster>,
    pub contexts: Vec<Context>,
    pub users: Vec<User>,
}

impl Config {
    pub fn from_reader<R>(r: R) -> Result<Config, KubeError>
    where
        R: Read,
    {
        serde_yaml::from_reader(r).map_err(KubeError::from)
    }

    pub fn from_file(path: &str) -> Result<Config, KubeError> {
        let f = File::open(path)?;
        Config::from_reader(f)
    }
}

#[derive(Debug, Deserialize)]
pub struct Cluster {
    pub name: String,
    #[serde(rename = "cluster")]
    pub conf: ClusterConf,
}

// needed for serde default
fn default_false() -> bool {
    false
}

#[derive(Debug, Deserialize)]
pub struct ClusterConf {
    #[serde(rename = "certificate-authority")]
    pub cert: Option<String>,
    #[serde(rename = "certificate-authority-data")]
    pub cert_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify", default = "default_false")]
    pub skip_tls: bool,
    pub server: String,
}

#[derive(Debug, Deserialize)]
pub struct Context {
    pub name: String,
    #[serde(rename = "context")]
    pub conf: ContextConf,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub name: String,
    #[serde(rename = "user")]
    pub conf: UserConf,
}

/// This represents what we can find in a user in the actual config file (note the Deserialize).
/// Hence all the optional fields.  At some point we should write a custom deserializer for this to
/// make it cleaner
#[derive(Debug, Deserialize, Clone)]
pub struct UserConf {
    pub token: Option<String>,

    #[serde(rename = "client-certificate")]
    pub client_cert: Option<String>,
    #[serde(rename = "client-key")]
    pub client_key: Option<String>,
    #[serde(rename = "client-certificate-data")]
    pub client_cert_data: Option<String>,
    #[serde(rename = "client-key-data")]
    pub client_key_data: Option<String>,

    pub username: Option<String>,
    pub password: Option<String>,

    #[serde(rename = "auth-provider")]
    pub auth_provider: Option<AuthProvider>,

    pub exec: Option<ExecConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContextConf {
    pub cluster: String,
    pub namespace: Option<String>,
    pub user: String,
}

// Classes to hold deserialized data for auth
#[derive(PartialEq, Debug, Deserialize, Clone)]
pub struct AuthProvider {
    name: String,
    pub token: RefCell<Option<String>>,
    pub expiry: RefCell<Option<DateTime<Local>>>,
    pub config: AuthProviderConfig,
}

#[derive(PartialEq, Debug, Deserialize, Clone)]
pub struct AuthProviderConfig {
    #[serde(rename = "access-token")]
    pub access_token: Option<String>,
    expiry: Option<String>,

    #[serde(rename = "cmd-args")]
    cmd_args: Option<String>,
    #[serde(rename = "cmd-path")]
    cmd_path: Option<String>,
    #[serde(rename = "expiry-key")]
    expiry_key: Option<String>,
    #[serde(rename = "token-key")]
    token_key: Option<String>,
}

impl AuthProvider {
    // Copy the token and expiry out of the config into the refcells
    pub fn copy_up(&self) {
        let mut token = self.token.borrow_mut();
        *token = self.config.access_token.clone();
        let mut expiry = self.expiry.borrow_mut();
        if let Some(expiry_str) = &self.config.expiry {
            match AuthProvider::parse_expiry(expiry_str.as_str()) {
                Ok(e) => *expiry = Some(e),
                Err(e) => {
                    eprintln!("Failed to parse expiry from config: {}", e);
                }
            }
        }
    }

    fn parse_expiry(expiry_str: &str) -> Result<DateTime<Local>, KubeError> {
        // Somehow google sometimes puts a date like "2018-03-31 22:22:01" in the config
        // and other times like "2018-04-01T05:57:31Z", so we have to try both.  wtf google.
        if let Ok(expiry) = DateTime::parse_from_rfc3339(expiry_str) {
            Ok(expiry.with_timezone(&Local))
        } else if let Ok(expiry) = Local.datetime_from_str(expiry_str, "%Y-%m-%d %H:%M:%S") {
            Ok(expiry)
        } else {
            Err(KubeError::ParseErr(format!(
                "Cannot parse expiry: {}",
                expiry_str
            )))
        }
    }

    fn is_expired(&self) -> bool {
        let expiry = self.expiry.borrow();
        match *expiry {
            Some(e) => {
                let now = Local::now();
                e < now
            }
            None => {
                eprintln!("No expiry, cannot validate if token is still valid, assuming expired");
                true
            }
        }
    }

    // Turn a {.credential.expiry_key} type string into a serde_json pointer string like
    // /credential/expiry_key
    fn make_pointer(s: &str) -> String {
        if s.len() < 2 {
            s.to_string()
        } else {
            let l = s.len() - 1;
            let split = &s[1..l].split('.');
            split.clone().collect::<Vec<&str>>().join("/")
        }
    }

    fn parse_output_and_update(
        &self,
        output: &str,
        token: &mut Option<String>,
        expiry: &mut Option<DateTime<Local>>,
    ) {
        let v: Value = serde_json::from_str(output).unwrap();
        let mut updated_token = false;
        match self.config.token_key.as_ref() {
            Some(tk) => {
                let token_pntr = AuthProvider::make_pointer(tk.as_str());
                let extracted_token = v.pointer(token_pntr.as_str()).and_then(|tv| tv.as_str());
                *token = extracted_token.map(|t| t.to_owned());
                updated_token = true;
            }
            None => {
                println!("No token-key in auth-provider, cannot extract token");
            }
        }

        if updated_token {
            match self.config.expiry_key.as_ref() {
                Some(ek) => {
                    let expiry_pntr = AuthProvider::make_pointer(ek.as_str());
                    let extracted_expiry =
                        v.pointer(expiry_pntr.as_str()).and_then(|ev| ev.as_str());
                    match extracted_expiry {
                        Some(extracted_expiry) => {
                            match AuthProvider::parse_expiry(extracted_expiry) {
                                Ok(e) => *expiry = Some(e),
                                Err(e) => {
                                    eprintln!("Failed to parse expiry from returned json: {}", e);
                                }
                            }
                        }
                        None => {
                            eprintln!("Config did not contain an expiry at: {}", expiry_pntr);
                        }
                    }
                }
                None => {
                    println!(
                        "No expiry-key in config, will have to pull a new \
                         token on every command"
                    );
                }
            }
        }
    }

    fn update_token(&self, token: &mut Option<String>, expiry: &mut Option<DateTime<Local>>) {
        match self.config.cmd_path {
            Some(ref conf_cmd) => {
                let args = self
                    .config
                    .cmd_args
                    .as_ref()
                    .map(|argstr| argstr.split_whitespace().collect())
                    .unwrap_or_else(Vec::new);
                match ductcmd(conf_cmd, &args).read() {
                    Ok(output) => {
                        self.parse_output_and_update(output.as_str(), token, expiry);
                    }
                    Err(e) => {
                        println!("Failed to run update command: {}", e);
                    }
                }
            }
            None => {
                println!("No update command specified, can't update");
            }
        }
    }

    /// Checks that we have a valid token, and if not, attempts to update it based on the config
    pub fn ensure_token(&self) -> Option<String> {
        let mut token = self.token.borrow_mut();
        if token.is_none() || self.is_expired() {
            // update
            let mut expiry = self.expiry.borrow_mut();
            *token = None;
            self.update_token(&mut token, &mut expiry)
        }
        token.clone()
    }
}

#[derive(PartialEq, Debug, Deserialize, Clone)]
pub struct NameValue {
    name: String,
    value: String,
}

/// config for running a command, as defined here:
/// https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/client-go/tools/clientcmd/api/v1/types.go#L183
#[derive(PartialEq, Debug, Deserialize, Clone)]
pub struct ExecConfig {
    command: Option<String>,
    args: Option<Vec<String>>,
    env: Option<Vec<NameValue>>,
    #[serde(rename = "apiVersion")]
    api_version: Option<String>,
}

/// Result of executing above. Schema defined here:
/// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#tokenrequest-v1-authentication-k8s-io
#[allow(dead_code)]
#[derive(Deserialize)]
struct ExecResult {
    kind: Option<String>,
    #[serde(rename = "apiVersion")]
    api_version: Option<String>,
    status: Option<ExecResultStatus>,
}

#[derive(Deserialize)]
struct ExecResultStatus {
    #[serde(rename = "expirationTimestamp")]
    expiration: Option<DateTime<Local>>,
    token: Option<String>,
    #[serde(rename = "clientCertificateData")]
    pub client_certificate_data: Option<String>,
    #[serde(rename = "clientKeyData")]
    pub client_key_data: Option<String>,
}

impl ExecConfig {
    fn exec(&self) -> Result<ExecResult, KubeError> {
        match self.command {
            Some(ref command) => {
                let expr = if let Some(args) = &self.args {
                    ductcmd(command, args)
                } else {
                    let args: Vec<String> = vec![];
                    ductcmd(command, args)
                };
                let expr = if let Some(env) = &self.env {
                    let env = env.iter().map(|nv| (&nv.name, &nv.value));
                    expr.full_env(env)
                } else {
                    expr
                };

                serde_json::from_reader(expr.reader()?).map_err(KubeError::from)
            }
            None => Err(KubeError::ConfigFileError(
                "No command specified in exec config".to_string(),
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExecAuth {
    Token(String),
    ClientCertKey {
        cert: Certificate,
        key: PrivateKey,
        cert_data: String,
        key_data: String,
    },
}

impl ExecAuth {
    fn default() -> ExecAuth {
        ExecAuth::Token("".to_string())
    }
}

#[derive(Clone, Debug)]
pub struct ExecProvider {
    pub auth: RefCell<Option<ExecAuth>>,
    pub expiry: RefCell<Option<DateTime<Local>>>,
    pub config: ExecConfig,
}

impl ExecProvider {
    pub fn new(config: ExecConfig) -> ExecProvider {
        ExecProvider {
            auth: RefCell::new(None),
            expiry: RefCell::new(None),
            config,
        }
    }

    fn is_expired(&self) -> bool {
        let expiry = self.expiry.borrow();
        match *expiry {
            Some(e) => {
                let now = Local::now();
                e < now
            }
            None => true,
        }
    }

    fn update_auth(&self) {
        match self.config.exec() {
            Ok(result) => {
                match result.status {
                    Some(status) => {
                        if status.expiration.is_none() {
                            eprintln!(
                                "exec command returned no expiration. future commands will refetch token."
                            );
                        }
                        if let Some(token) = status.token {
                            *self.auth.borrow_mut() = Some(ExecAuth::Token(token));
                        } else if let Some(cert_data) = status.client_certificate_data {
                            if status.client_key_data.is_none() {
                                eprintln!("exec returned certificate but no key, can't auth.");
                                return;
                            }
                            let key_data = status.client_key_data.unwrap();

                            let cert = crate::certs::get_cert_from_pem(&cert_data);
                            if cert.is_none() {
                                eprintln!("Can't decode returned certificate data.");
                                return;
                            }

                            let key = crate::certs::get_key_from_str(&key_data);
                            if key.is_none() {
                                eprintln!("Can't decode returned key data.");
                                return;
                            }
                            *self.auth.borrow_mut() = Some(ExecAuth::ClientCertKey {
                                cert: cert.unwrap(), // checked above
                                key: key.unwrap(),   // checked above
                                cert_data,
                                key_data,
                            });
                        }
                        *self.expiry.borrow_mut() = status.expiration;
                    }
                    None => {
                        eprintln!("No status block returned by exec, can't update auth");
                    }
                }
            }
            Err(e) => {
                println!("Error running specified exec command: {}", e);
            }
        }
    }

    pub fn get_auth(&self) -> (ExecAuth, bool) {
        let was_expired = if self.is_expired() {
            self.update_auth();
            true
        } else {
            false
        };
        // TODO: Fix kube.rs to be able to handle an option here
        match &*self.auth.borrow() {
            Some(auth) => (auth.clone(), was_expired),
            None => (ExecAuth::default(), was_expired),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_CONFIG: &str = r"apiVersion: v1
clusters:
- cluster:
    certificate-authority: ../relative/ca.cert
    server: https://cluster1.test:443
  name: cluster1
- cluster:
    certificate-authority: /absolute-path/ca.pem
    server: https://cluster2.foo:8443
  name: cluster2
- cluster:
    insecure-skip-tls-verify: true
    server: https://insecure.blah
  name: insecure
- cluster:
    certificate-authority-data: aGVsbG8K
    server: http://nos.foo:80
  name: data
contexts:
- context:
    cluster: cluster1
    user: c1user
    namespace: ns1
  name: c1ctx
- context:
    cluster: cluster2
    user: c2user
  name: c2ctx
current-context: c1ctx
users:
- name: c1user
  user:
    client-certificate: ../relative/c1.cert
    client-key: ../relative/c1.key
- name: token
  user:
    token: DEADBEEF
- name: keydata
  user:
    client-certificate-data: CERTDATA
    client-key-data: KEYDATA
- name: userpass
  user:
    username: user
    password: hunter2
- name: gke
  user:
    auth-provider:
      name: gke-provider
      config:
        cmd-args: config config-helper --format=json
        cmd-path: /bin/gcloud
        expiry-key: '{.credential.token_expiry}'
        token-key: '{.credential.access_token}'
- name: exec
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - --region
      - us-west-2
      - eks
      - get-token
      - --cluster-name
      - test-cluster
      command: aws
      env: null
";

    fn contains_cluster(config: &Config, cluster: Cluster) -> bool {
        for c in config.clusters.iter() {
            if c.name == cluster.name {
                if c.conf.cert == cluster.conf.cert
                    && c.conf.cert_data == cluster.conf.cert_data
                    && c.conf.skip_tls == cluster.conf.skip_tls
                    && c.conf.server == cluster.conf.server
                {
                    return true;
                }
            }
        }
        return false;
    }

    fn contains_context(config: &Config, context: Context) -> bool {
        for c in config.contexts.iter() {
            if c.name == context.name {
                if c.conf.cluster == context.conf.cluster
                    && c.conf.user == context.conf.user
                    && c.conf.namespace == context.conf.namespace
                {
                    return true;
                }
            }
        }
        return false;
    }

    fn contains_user(config: &Config, user: User) -> bool {
        for u in config.users.iter() {
            if u.name == user.name {
                if u.conf.token == user.conf.token
                    && u.conf.client_cert == user.conf.client_cert
                    && u.conf.client_key == user.conf.client_key
                    && u.conf.client_cert_data == user.conf.client_cert_data
                    && u.conf.client_key_data == user.conf.client_key_data
                    && u.conf.username == user.conf.username
                    && u.conf.password == user.conf.password
                    && u.conf.auth_provider == user.conf.auth_provider
                {
                    return true;
                }
            }
        }
        return false;
    }

    #[test]
    fn test_parse_config() {
        let config = Config::from_reader(TEST_CONFIG.as_bytes());
        if config.is_err() {
            println!("Failed to parse config: {:?}", config);
            assert!(config.is_ok()); // will always fail
        }
        let config = config.unwrap();
        assert!(contains_cluster(
            &config,
            Cluster {
                name: "data".to_string(),
                conf: ClusterConf {
                    cert: None,
                    cert_data: Some("aGVsbG8K".to_string()),
                    skip_tls: false,
                    server: "http://nos.foo:80".to_string(),
                }
            }
        ));
        assert!(contains_cluster(
            &config,
            Cluster {
                name: "cluster1".to_string(),
                conf: ClusterConf {
                    cert: Some("../relative/ca.cert".to_string()),
                    cert_data: None,
                    skip_tls: false,
                    server: "https://cluster1.test:443".to_string(),
                }
            }
        ));
        assert!(contains_cluster(
            &config,
            Cluster {
                name: "cluster2".to_string(),
                conf: ClusterConf {
                    cert: Some("/absolute-path/ca.pem".to_string()),
                    cert_data: None,
                    skip_tls: false,
                    server: "https://cluster2.foo:8443".to_string(),
                }
            }
        ));
        assert!(contains_cluster(
            &config,
            Cluster {
                name: "insecure".to_string(),
                conf: ClusterConf {
                    cert: None,
                    cert_data: None,
                    skip_tls: true,
                    server: "https://insecure.blah".to_string(),
                }
            }
        ));
        assert!(contains_context(
            &config,
            Context {
                name: "c1ctx".to_string(),
                conf: ContextConf {
                    cluster: "cluster1".to_string(),
                    user: "c1user".to_string(),
                    namespace: Some("ns1".to_string()),
                }
            }
        ));
        assert!(contains_context(
            &config,
            Context {
                name: "c2ctx".to_string(),
                conf: ContextConf {
                    cluster: "cluster2".to_string(),
                    user: "c2user".to_string(),
                    namespace: None,
                }
            }
        ));
        assert!(contains_user(
            &config,
            User {
                name: "c1user".to_string(),
                conf: UserConf {
                    token: None,
                    client_cert: Some("../relative/c1.cert".to_string()),
                    client_key: Some("../relative/c1.key".to_string()),
                    client_cert_data: None,
                    client_key_data: None,
                    username: None,
                    password: None,
                    auth_provider: None,
                    exec: None,
                }
            }
        ));
        assert!(contains_user(
            &config,
            User {
                name: "token".to_string(),
                conf: UserConf {
                    token: Some("DEADBEEF".to_string()),
                    client_cert: None,
                    client_key: None,
                    client_cert_data: None,
                    client_key_data: None,
                    username: None,
                    password: None,
                    auth_provider: None,
                    exec: None,
                }
            }
        ));
        assert!(contains_user(
            &config,
            User {
                name: "keydata".to_string(),
                conf: UserConf {
                    token: None,
                    client_cert: None,
                    client_key: None,
                    client_cert_data: Some("CERTDATA".to_string()),
                    client_key_data: Some("KEYDATA".to_string()),
                    username: None,
                    password: None,
                    auth_provider: None,
                    exec: None,
                }
            }
        ));
        assert!(contains_user(
            &config,
            User {
                name: "userpass".to_string(),
                conf: UserConf {
                    token: None,
                    client_cert: None,
                    client_key: None,
                    client_cert_data: None,
                    client_key_data: None,
                    username: Some("user".to_string()),
                    password: Some("hunter2".to_string()),
                    auth_provider: None,
                    exec: None,
                }
            }
        ));
    }

    #[test]
    fn make_pointer() {
        let p = AuthProvider::make_pointer("{.credential.expiry_key}");
        assert_eq!(p, "/credential/expiry_key");

        let p = AuthProvider::make_pointer("");
        assert_eq!(p, "");

        let p = AuthProvider::make_pointer("{}");
        assert_eq!(p, "");

        let p = AuthProvider::make_pointer("{blah}");
        assert_eq!(p, "blah");

        let p = AuthProvider::make_pointer("{.blah}");
        assert_eq!(p, "/blah");

        let p = AuthProvider::make_pointer("{blah.foo}");
        assert_eq!(p, "blah/foo");
    }

    #[test]
    fn parse_output_and_update() {
        let ap = AuthProvider {
            name: "name".to_string(),
            token: RefCell::new(None),
            expiry: RefCell::new(None),
            config: AuthProviderConfig {
                access_token: None,
                expiry: None,
                cmd_args: None,
                cmd_path: None,
                expiry_key: Some("{.credential.token_expiry}".to_string()),
                token_key: Some("{.credential.access_token}".to_string()),
            },
        };
        {
            // scope for token/expiry borrow
            let mut token = ap.token.borrow_mut();
            let mut expiry = ap.expiry.borrow_mut();
            ap.parse_output_and_update(
                r#"{
  "configuration": {
    "active_configuration": "default",
    "properties": {
      "core": {
        "account": "test@example.com",
        "disable_usage_reporting": "True",
        "project": "test-project-foo"
      }
    }
  },
  "credential": {
    "access_token": "THETOKEN",
    "token_expiry": "2019-12-29T23:38:43Z"
  },
  "sentinels": {
    "config_sentinel": "/home/user/.config/gcloud/config_sentinel"
  }
}"#,
                &mut token,
                &mut expiry,
            );
        }
        assert_eq!(ap.token, RefCell::new(Some("THETOKEN".to_string())));
        assert_eq!(
            ap.expiry,
            RefCell::new(Some(
                DateTime::parse_from_rfc3339("2019-12-29T23:38:43Z")
                    .unwrap()
                    .with_timezone(&Local)
            ))
        );
    }

    #[test]
    fn copy_up() {
        let ap = AuthProvider {
            name: "name".to_string(),
            token: RefCell::new(None),
            expiry: RefCell::new(None),
            config: AuthProviderConfig {
                access_token: Some("CTOKEN".to_string()),
                expiry: Some("2019-12-29T23:24:25Z".to_string()),
                cmd_args: None,
                cmd_path: None,
                expiry_key: None,
                token_key: None,
            },
        };
        ap.copy_up();
        assert_eq!(ap.token, RefCell::new(Some("CTOKEN".to_string())));
        assert_eq!(
            ap.expiry,
            RefCell::new(Some(
                DateTime::parse_from_rfc3339("2019-12-29T23:24:25Z")
                    .unwrap()
                    .with_timezone(&Local)
            ))
        );
    }

    #[test]
    fn parse_expiry() {
        let e = AuthProvider::parse_expiry("2018-04-01T05:57:31Z");
        assert_eq!(
            e.unwrap(),
            DateTime::parse_from_rfc3339("2018-04-01T05:57:31Z").unwrap()
        );

        let e = AuthProvider::parse_expiry("2018-04-01 5:57:31");
        assert_eq!(
            e.unwrap(),
            Local
                .datetime_from_str("2018-04-01 5:57:31", "%Y-%m-%d %H:%M:%S")
                .unwrap()
        );

        let fe = AuthProvider::parse_expiry("INVALID");
        assert!(fe.is_err());
    }

    #[test]
    fn is_expired() {
        let ap = AuthProvider {
            name: "name".to_string(),
            token: RefCell::new(None),
            expiry: RefCell::new(Some(Local::now() - chrono::Duration::hours(1))),
            config: AuthProviderConfig {
                access_token: None,
                expiry: None,
                cmd_args: None,
                cmd_path: None,
                expiry_key: None,
                token_key: None,
            },
        };
        assert!(ap.is_expired());

        let ap = AuthProvider {
            name: "name".to_string(),
            token: RefCell::new(None),
            expiry: RefCell::new(Some(Local::now() + chrono::Duration::hours(1))),
            config: AuthProviderConfig {
                access_token: None,
                expiry: None,
                cmd_args: None,
                cmd_path: None,
                expiry_key: None,
                token_key: None,
            },
        };
        assert!(!ap.is_expired());
    }

    #[test]
    fn exec_parse() {
        let config = Config::from_reader(TEST_CONFIG.as_bytes()).unwrap();
        let exec_config = config.users.iter().find(|u| u.name == "exec");
        assert!(exec_config.is_some());
        let provider = ExecProvider {
            auth: RefCell::new(None),
            expiry: RefCell::new(None),
            config: exec_config.unwrap().conf.exec.as_ref().unwrap().clone(),
        };

        let (auth, was_expired) = provider.get_auth();
        assert!(was_expired);
        assert_eq!(auth, ExecAuth::Token("testtoken".to_string()));
    }

    #[test]
    fn exec_expired() {
        let config = Config::from_reader(TEST_CONFIG.as_bytes()).unwrap();
        let exec_config = config.users.iter().find(|u| u.name == "exec");
        assert!(exec_config.is_some());
        let provider = ExecProvider {
            auth: RefCell::new(Some(ExecAuth::Token("old-token".to_string()))),
            expiry: RefCell::new(Some(Local::now() - chrono::Duration::hours(1))),
            config: exec_config.unwrap().conf.exec.as_ref().unwrap().clone(),
        };

        let (auth, was_expired) = provider.get_auth();
        assert!(was_expired);
        assert_eq!(auth, ExecAuth::Token("testtoken".to_string()));
    }
}
