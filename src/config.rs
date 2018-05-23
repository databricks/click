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

//! Handle reading .kube/config files

use chrono::{DateTime, Local, TimeZone};
use chrono::offset::Utc;
use duct::cmd;
use serde_json::{self, Value};
use serde_yaml;

use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::From;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Read};

use error::{KubeErrNo, KubeError};
use kube::{Kluster, KlusterAuth};
use certs::{get_cert, get_cert_from_pem, get_key_from_str, get_private_key};

/// Kubernetes cluster config
#[derive(Debug, Deserialize)]
struct IConfig {
    clusters: Vec<ICluster>,
    contexts: Vec<IContext>,
    users: Vec<IUser>,
}

#[derive(Debug, Deserialize)]
struct ICluster {
    name: String,
    #[serde(rename = "cluster")] conf: IClusterConf,
}

#[derive(Debug, Deserialize)]
struct IClusterConf {
    #[serde(rename = "certificate-authority")] pub cert: Option<String>,
    #[serde(rename = "certificate-authority-data")] pub cert_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify")] pub skip_tls: Option<bool>,
    pub server: String,
}

#[derive(Debug)]
pub struct ClusterConf {
    pub cert: Option<String>,
    pub server: String,
    pub insecure_skip_tls_verify: bool,
}

impl ClusterConf {
    fn new(cert: Option<String>, server: String) -> ClusterConf {
        ClusterConf {
            cert: cert,
            server: server,
            insecure_skip_tls_verify: false,
        }
    }

    fn new_insecure(cert: Option<String>, server: String) -> ClusterConf {
        ClusterConf {
            cert: cert,
            server: server,
            insecure_skip_tls_verify: true,
        }
    }
}

#[derive(Debug, Deserialize)]
struct IContext {
    name: String,
    #[serde(rename = "context")] conf: ContextConf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContextConf {
    pub cluster: String,
    //#[serde(default = "default")]
    pub namespace: Option<String>,
    pub user: String,
}

#[derive(Debug, Deserialize)]
struct IUser {
    name: String,
    #[serde(rename = "user")] conf: IUserConf,
}

// Classes to hold deserialized data for auth
#[derive(Debug, Deserialize, Clone)]
pub struct AuthProvider {
    name: String,
    pub token: RefCell<Option<String>>,
    pub expiry: RefCell<Option<String>>,
    pub config: AuthProviderConfig,
}

impl AuthProvider {
    // Copy the token and expiry out of the config into the refcells
    fn copy_up(&self) {
        let mut token = self.token.borrow_mut();
        *token = self.config.access_token.clone();
        let mut expiry = self.expiry.borrow_mut();
        *expiry = self.config.expiry.clone();
    }

    // true if expiry is before now
    fn check_dt<T: TimeZone>(&self, expiry: DateTime<T>) -> bool {
        let etime = expiry.with_timezone(&Utc);
        let now = Utc::now();
        etime < now
    }

    fn is_expired(&self) -> bool {
        let expiry = self.expiry.borrow();
        match *expiry {
            Some(ref e) => {
                // Somehow google sometimes puts a date like "2018-03-31 22:22:01" in the config
                // and other times like "2018-04-01T05:57:31Z", so we have to try both.  wtf google.
                if let Ok(expiry) = DateTime::parse_from_rfc3339(e) {
                    self.check_dt(expiry)
                } else if let Ok(expiry) = Local.datetime_from_str(e, "%Y-%m-%d %H:%M:%S") {
                    self.check_dt(expiry)
                } else {
                    true
                }
            }
            None => {
                println!("No expiry set, cannot validate if token is still valid");
                false
            }
        }
    }

    // Turn a {.credential.expiry_key} type string into a serde_json pointer string like
    // /credential/expiry_key
    fn make_pointer(&self, s: &str) -> String {
        let l = s.len() - 1;
        let split = &s[1..l].split('.');
        split.clone().collect::<Vec<&str>>().join("/")
    }

    fn update_token(&self, token: &mut Option<String>, expiry: &mut Option<String>) {
        match self.config.cmd_path {
            Some(ref conf_cmd) => {
                let args = self.config
                    .cmd_args
                    .as_ref()
                    .map(|argstr| argstr.split_whitespace().collect())
                    .unwrap_or(vec![]);
                match cmd(conf_cmd, &args).read() {
                    Ok(output) => {
                        let v: Value = serde_json::from_str(output.as_str()).unwrap();
                        let mut updated_token = false;
                        match self.config.token_key.as_ref() {
                            Some(ref tk) => {
                                let token_pntr = self.make_pointer(tk.as_str());
                                let extracted_token =
                                    v.pointer(token_pntr.as_str()).and_then(|tv| tv.as_str());
                                *token = extracted_token.map(|t| t.to_owned());
                                updated_token = true;
                            }
                            None => {
                                println!("No token-key in auth-provider, cannot extract token");
                            }
                        }

                        if updated_token {
                            match self.config.expiry_key.as_ref() {
                                Some(ref ek) => {
                                    let expiry_pntr = self.make_pointer(ek.as_str());
                                    let extracted_expiry =
                                        v.pointer(expiry_pntr.as_str()).and_then(|ev| ev.as_str());
                                    *expiry = extracted_expiry.map(|e| e.to_owned());
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
    pub fn ensure_token(&self) -> String {
        let mut token = self.token.borrow_mut();
        if token.is_none() || self.is_expired() {
            // update
            let mut expiry = self.expiry.borrow_mut();
            *token = None;
            self.update_token(&mut token, &mut expiry)
        }
        match token.as_ref() {
            Some(t) => t.clone(),
            None => {
                println!(
                    "Couldn't get an authentication token. You can try exiting Click and \
                     running a kubectl command against the cluster to refresh it. Also please \
                     report this error on the Click github page."
                );
                "".to_owned()
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthProviderConfig {
    #[serde(rename = "access-token")] pub access_token: Option<String>,
    expiry: Option<String>,

    #[serde(rename = "cmd-args")] cmd_args: Option<String>,
    #[serde(rename = "cmd-path")] cmd_path: Option<String>,
    #[serde(rename = "expiry-key")] expiry_key: Option<String>,
    #[serde(rename = "token-key")] token_key: Option<String>,
}

/// This represents what we can find in a user in the actual config file (note the Deserialize).
/// Hence all the optional fields.  At some point we should write a custom deserializer for this to
/// make it cleaner
#[derive(Debug, Deserialize, Clone)]
pub struct IUserConf {
    pub token: Option<String>,

    #[serde(rename = "client-certificate")] pub client_cert: Option<String>,
    #[serde(rename = "client-key")] pub client_key: Option<String>,
    #[serde(rename = "client-certificate-data")] pub client_cert_data: Option<String>,
    #[serde(rename = "client-key-data")] pub client_key_data: Option<String>,

    pub username: Option<String>,
    pub password: Option<String>,

    #[serde(rename = "auth-provider")] pub auth_provider: Option<AuthProvider>,
}

// These are the different kinds of authentication data  a user might have

/// KeyCert can be either raw data from a "client-*-data" field, or a path to a file with the data
/// from a "client-*" field.
#[derive(Debug)]
pub enum UserConf {
    Token(String),
    KeyCertPath(String, String),
    KeyCertData(String, String),
    UserPass(String, String),
    AuthProvider(AuthProvider),
    Unsupported,
}

impl From<IUserConf> for UserConf {
    fn from(iconf: IUserConf) -> UserConf {
        if let Some(token) = iconf.token {
            UserConf::Token(token)
        } else if let (Some(username), Some(password)) = (iconf.username, iconf.password) {
            UserConf::UserPass(username, password)
        } else if let (Some(client_cert_path), Some(key_path)) =
            (iconf.client_cert, iconf.client_key)
        {
            UserConf::KeyCertPath(client_cert_path, key_path)
        } else if let (Some(client_cert_data), Some(key_data)) =
            (iconf.client_cert_data, iconf.client_key_data)
        {
            UserConf::KeyCertData(client_cert_data, key_data)
        } else if let Some(auth_provider) = iconf.auth_provider {
            UserConf::AuthProvider(auth_provider)
        } else {
            UserConf::Unsupported
        }
    }
}

impl IConfig {
    fn from_file(path: &str) -> Result<IConfig, io::Error> {
        let f = File::open(path)?;
        serde_yaml::from_reader(f).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Couldn't read yaml: {}", e.description()),
            )
        })
    }
}

/// A kubernetes config
// This is actual config we expose
#[derive(Debug)]
pub struct Config {
    pub source_file: String,
    pub clusters: HashMap<String, ClusterConf>,
    pub contexts: HashMap<String, ContextConf>,
    pub users: HashMap<String, UserConf>,
}

// some utility functions
fn get_full_path(path: String) -> Result<String, KubeError> {
    if path.is_empty() {
        return Err(KubeError::ConfigFileError(
            "Empty certificate/key path".to_owned(),
        ));
    }
    // unwrap okay, validated above
    if path.chars().next().unwrap() == '/' {
        Ok(path)
    } else if let Some(home_dir) = env::home_dir() {
        Ok(format!("{}/.kube/{}", home_dir.as_path().display(), path))
    } else {
        return Err(KubeError::ConfigFileError(
            "Could not get path kubernetes \
             certificates/keys (not fully specified, and \
             your home directory is not known."
                .to_owned(),
        ));
    }
}

fn auth_from_paths(
    client_cert_path: String,
    key_path: String,
    context: &str,
) -> Result<KlusterAuth, KubeError> {
    if client_cert_path.len() == 0 {
        return Err(KubeError::ConfigFileError(format!(
            "Empty client certificate path for {}, can't continue",
            context
        )));
    }
    if key_path.len() == 0 {
        return Err(KubeError::ConfigFileError(format!(
            "Empty client key path for {}, can't continue",
            context
        )));
    }

    let cert_full_path = get_full_path(client_cert_path)?;
    let key_full_path = get_full_path(key_path)?;
    if let (Some(cert), Some(private_key)) = (
        get_cert(cert_full_path.as_str()),
        get_private_key(key_full_path.as_str()),
    ) {
        Ok(KlusterAuth::with_cert_and_key(cert, private_key))
    } else {
        Err(KubeError::ConfigFileError(format!(
            "Can't read/convert cert or private key for {}",
            context
        )))
    }
}

fn auth_from_data(
    client_cert_data: &String,
    key_data: &String,
    context: &str,
) -> Result<KlusterAuth, KubeError> {
    if client_cert_data.len() == 0 {
        Err(KubeError::ConfigFileError(format!(
            "Empty client certificate data for {}, can't continue",
            context
        )))
    } else if key_data.len() == 0 {
        Err(KubeError::ConfigFileError(format!(
            "Empty client key data for {}, can't continue",
            context
        )))
    } else {
        let mut cert_enc = ::base64::decode(client_cert_data.as_str())?;
        cert_enc.retain(|&i| i != 0);
        let cert_pem = String::from_utf8(cert_enc).map_err(|e| {
            KubeError::ConfigFileError(format!(
                "Invalid utf8 data in certificate: {}",
                e.description()
            ))
        })?;
        let cert = get_cert_from_pem(cert_pem.as_str());
        let mut key_enc = ::base64::decode(key_data.as_str())?;
        key_enc.retain(|&i| i != 0);
        let key_str = String::from_utf8(key_enc).map_err(|e| {
            KubeError::ConfigFileError(format!("Invalid utf8 data in key: {}", e.description()))
        })?;
        let key = get_key_from_str(key_str.as_str());
        match (cert, key) {
            (Some(c), Some(k)) => Ok(KlusterAuth::with_cert_and_key(c, k)),
            _ => Err(KubeError::ConfigFileError(format!(
                "Invalid certificate or key data for context: {}",
                context
            ))),
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Config, KubeError> {
        let iconf = IConfig::from_file(path)?;

        // copy over clusters
        let mut cluster_map = HashMap::new();
        for cluster in iconf.clusters.into_iter() {
            // make sure we've specified one of:
            //  - a cert file
            //  - cert data
            //  - insecure-skip-tls-verify
            let has_cd = cluster.conf.cert_data.is_some();
            match (cluster.conf.cert, cluster.conf.cert_data) {
                (Some(cert_config_path), _) => {
                    if has_cd {
                        println!(
                            "Cluster {} specifies a certificate path and certificate data, \
                             ignoring data and using the path",
                            cluster.name
                        );
                    }
                    let cert_path = get_full_path(cert_config_path)?;
                    match File::open(cert_path) {
                        Ok(f) => {
                            let mut br = BufReader::new(f);
                            let mut s = String::new();
                            br.read_to_string(&mut s).expect("Couldn't read cert");
                            cluster_map.insert(
                                cluster.name.clone(),
                                ClusterConf::new(Some(s), cluster.conf.server),
                            );
                        }
                        Err(e) => {
                            println!(
                                "Invalid server cert path for cluster {}: {}.\nAny contexts using \
                                 this cluster will be unavailable.",
                                cluster.name,
                                e.description()
                            );
                        }
                    }
                }
                (None, Some(cert_data)) => match ::base64::decode(cert_data.as_str()) {
                    Ok(mut cert) => {
                        cert.retain(|&i| i != 0);
                        let cert_pem = String::from_utf8(cert).map_err(|e| {
                            KubeError::ConfigFileError(format!(
                                "Invalid utf8 data in certificate: {}",
                                e.description()
                            ))
                        })?;
                        cluster_map.insert(
                            cluster.name.clone(),
                            ClusterConf::new(Some(cert_pem), cluster.conf.server),
                        );
                    }
                    Err(e) => {
                        println!(
                            "Invalid certificate data, could not base64 decode: {}",
                            e.description()
                        );
                    }
                },
                (None, None) => {
                    let conf = if cluster.conf.skip_tls.unwrap_or(false) {
                        ClusterConf::new_insecure(None, cluster.conf.server)
                    } else {
                        ClusterConf::new(None, cluster.conf.server)
                    };
                    cluster_map.insert(cluster.name.clone(), conf);
                }
            }
        }

        // copy over contexts
        let mut context_map = HashMap::new();
        for context in iconf.contexts.iter() {
            context_map.insert(context.name.clone(), context.conf.clone());
        }

        // copy over users
        let mut user_map = HashMap::new();
        for user in iconf.users.into_iter() {
            user_map.insert(user.name.clone(), user.conf.into());
        }

        Ok(Config {
            source_file: path.to_owned(),
            clusters: cluster_map,
            contexts: context_map,
            users: user_map,
        })
    }

    pub fn from_files(paths: &Vec<String>) -> Result<Config, KubeError> {
        let configs = paths
            .into_iter()
            .map(|config_path| {
                Config::from_file(config_path.as_str())
                    .map_err(|e| KubeError::ConfigFileError(format!(
                        "Could not load {}, reason: {}",
                        config_path, 
                        e.description()))
                    )
            })
            .collect::<Result<Vec<_>,_>>()?;

        let empty_config = Config{
            source_file: String::new(),
            clusters: HashMap::new(),
            contexts: HashMap::new(),
            users: HashMap::new(),
        };

        let mut source_vector = Vec::new();
        let mut merged_config: Config = configs
            .into_iter()
            .fold(empty_config, |mut resulting_config, item| {
                source_vector.push(item.source_file);
                resulting_config.clusters.extend(item.clusters);
                resulting_config.contexts.extend(item.contexts);
                resulting_config.users.extend(item.users);

                resulting_config
            });

        let sources = env::join_paths(source_vector.into_iter())?.into_string()?;

        merged_config.source_file = sources;

        Ok(merged_config)
    }

    pub fn cluster_for_context(&self, context: &str) -> Result<Kluster, KubeError> {
        self.contexts
            .get(context)
            .map(|ctx| {
                self.clusters
                    .get(&ctx.cluster)
                    .map(|cluster| {
                        self.users
                            .get(&ctx.user)
                            .map(|user| {
                                let auth = match user {
                                    &UserConf::Token(ref token) => {
                                        Ok(KlusterAuth::with_token(token.as_str()))
                                    }
                                    &UserConf::UserPass(ref username, ref password) => {
                                        Ok(KlusterAuth::with_userpass(username, password))
                                    }
                                    &UserConf::KeyCertPath(ref cert_path, ref key_path) => {
                                        auth_from_paths(
                                            cert_path.clone(),
                                            key_path.clone(),
                                            context,
                                        )
                                    }
                                    &UserConf::KeyCertData(ref cert_data, ref key_data) => {
                                        auth_from_data(cert_data, key_data, context)
                                    }
                                    &UserConf::AuthProvider(ref provider) => {
                                        provider.copy_up();
                                        Ok(KlusterAuth::with_auth_provider(provider.clone()))
                                    }
                                    _ => Err(KubeError::ConfigFileError(format!(
                                        "Invalid context {}.  Each user must have either a token, \
                                         a username AND password, or a client-certificate AND \
                                         a client-key, or an auth-provider",
                                        context
                                    ))),
                                }?;
                                Kluster::new(
                                    context,
                                    cluster.cert.clone(),
                                    cluster.server.as_str(),
                                    auth,
                                    cluster.insecure_skip_tls_verify,
                                )
                            })
                            .ok_or(KubeError::Kube(KubeErrNo::InvalidUser))
                    })
                    .ok_or(KubeError::Kube(KubeErrNo::InvalidCluster))
            })
            .ok_or(KubeError::Kube(KubeErrNo::InvalidContextName))
            .and_then(|n| n)
            .and_then(|n| n)
            .and_then(|n| n)
    }
}

/// Click config
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ClickConfig {
    pub namespace: Option<String>,
    pub context: Option<String>,
    pub editor: Option<String>,
    pub terminal: Option<String>,
}

impl ClickConfig {
    pub fn from_file(path: &str) -> ClickConfig {
        match File::open(path) {
            Ok(f) => match serde_yaml::from_reader(f) {
                Ok(c) => c,
                Err(e) => {
                    println!("Could not read config file {:?}, using default values", e);
                    ClickConfig::default()
                }
            },
            Err(e) => {
                println!(
                    "Could not open config file at '{}': {}. Using default values",
                    path, e
                );
                ClickConfig::default()
            }
        }
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), KubeError> {
        let mut file = try!(File::create(path));
        try!(serde_yaml::to_writer(&mut file, &self));
        Ok(())
    }
}
