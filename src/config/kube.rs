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

//! Code to represent the data found in .kube/config files after it's deserialized, validated, and
//! so on.  Data in here is what gets passed around to the rest of Click.

use std::collections::HashMap;
use std::convert::From;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};

use certs::{get_cert, get_cert_from_pem, get_key_from_str, get_private_key};
use config::ClickConfig;
use error::{KubeErrNo, KubeError};
use kube::{ClientCertKey, Kluster, KlusterAuth};

use super::kubefile::{AuthProvider, ExecProvider};

#[derive(Debug)]
pub struct ClusterConf {
    pub cert: Option<String>,
    pub server: String,
    pub insecure_skip_tls_verify: bool,
}

impl ClusterConf {
    fn new(cert: Option<String>, server: String) -> ClusterConf {
        ClusterConf {
            cert,
            server,
            insecure_skip_tls_verify: false,
        }
    }

    fn new_insecure(cert: Option<String>, server: String) -> ClusterConf {
        ClusterConf {
            cert,
            server,
            insecure_skip_tls_verify: true,
        }
    }
}

// These are the different kinds of authentication data  a user might have

/// KeyCert can be either raw data from a "client-*-data" field, or a path to a file with the data
/// from a "client-*" field.
#[derive(Debug)]
pub enum UserAuth {
    Token(String),
    KeyCertPath(String, String),
    KeyCertData(String, String),
    UserPass(String, String),
    AuthProvider(Box<AuthProvider>),
    ExecProvider(ExecProvider),
}

#[derive(Debug)]
pub struct UserConf {
    auths: Vec<UserAuth>,
}

impl From<super::kubefile::UserConf> for UserConf {
    fn from(conf: super::kubefile::UserConf) -> UserConf {
        let mut auth_vec = vec![];

        if let Some(token) = conf.token {
            auth_vec.push(UserAuth::Token(token))
        }
        if let (Some(username), Some(password)) = (conf.username, conf.password) {
            auth_vec.push(UserAuth::UserPass(username, password))
        }
        if let (Some(client_cert_path), Some(key_path)) = (conf.client_cert, conf.client_key) {
            auth_vec.push(UserAuth::KeyCertPath(client_cert_path, key_path))
        }
        if let (Some(client_cert_data), Some(key_data)) =
            (conf.client_cert_data, conf.client_key_data)
        {
            auth_vec.push(UserAuth::KeyCertData(client_cert_data, key_data))
        }
        if let Some(auth_provider) = conf.auth_provider {
            auth_vec.push(UserAuth::AuthProvider(Box::new(auth_provider)))
        }
        if let Some(exec_conf) = conf.exec {
            auth_vec.push(UserAuth::ExecProvider(ExecProvider::new(exec_conf)))
        }
        UserConf { auths: auth_vec }
    }
}

/// A kubernetes config
// This is actual config we expose
#[derive(Debug)]
pub struct Config {
    pub source_file: String,
    pub clusters: HashMap<String, ClusterConf>,
    pub contexts: HashMap<String, super::kubefile::ContextConf>,
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
    if path.starts_with('/') {
        Ok(path)
    } else if let Some(home_dir) = dirs::home_dir() {
        Ok(format!("{}/.kube/{}", home_dir.as_path().display(), path))
    } else {
        Err(KubeError::ConfigFileError(
            "Could not get path kubernetes \
             certificates/keys (not fully specified, and \
             your home directory is not known."
                .to_owned(),
        ))
    }
}

fn cert_key_from_paths(
    client_cert_path: String,
    key_path: String,
    context: &str,
) -> Result<ClientCertKey, KubeError> {
    if client_cert_path.is_empty() {
        return Err(KubeError::ConfigFileError(format!(
            "Empty client certificate path for {}, can't continue",
            context
        )));
    }
    if key_path.is_empty() {
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
        Ok(ClientCertKey::with_cert_and_key(cert, private_key))
    } else {
        Err(KubeError::ConfigFileError(format!(
            "Can't read/convert cert or private key for {}",
            context
        )))
    }
}

fn cert_key_from_data(
    client_cert_data: &str,
    key_data: &str,
    context: &str,
) -> Result<ClientCertKey, KubeError> {
    if client_cert_data.is_empty() {
        Err(KubeError::ConfigFileError(format!(
            "Empty client certificate data for {}, can't continue",
            context
        )))
    } else if key_data.is_empty() {
        Err(KubeError::ConfigFileError(format!(
            "Empty client key data for {}, can't continue",
            context
        )))
    } else {
        let mut cert_enc = ::base64::decode(client_cert_data)?;
        cert_enc.retain(|&i| i != 0);
        let cert_pem = String::from_utf8(cert_enc).map_err(|e| {
            KubeError::ConfigFileError(format!("Invalid utf8 data in certificate: {}", e))
        })?;
        let cert = get_cert_from_pem(cert_pem.as_str());
        let mut key_enc = ::base64::decode(key_data)?;
        key_enc.retain(|&i| i != 0);
        let key_str = String::from_utf8(key_enc)
            .map_err(|e| KubeError::ConfigFileError(format!("Invalid utf8 data in key: {}", e)))?;
        let key = get_key_from_str(key_str.as_str());
        match (cert, key) {
            (Some(c), Some(k)) => Ok(ClientCertKey::with_cert_and_key(c, k)),
            _ => Err(KubeError::ConfigFileError(format!(
                "Invalid certificate or key data for context: {}",
                context
            ))),
        }
    }
}

impl Config {
    pub fn from_files(paths: &[String]) -> Result<Config, KubeError> {
        let iconfs = paths
            .iter()
            .map(|config_path| super::kubefile::Config::from_file(config_path))
            .collect::<Result<Vec<_>, _>>()?;

        // copy over clusters
        let mut cluster_map = HashMap::new();
        for iconf in iconfs.iter() {
            for cluster in iconf.clusters.iter() {
                // make sure we've specified one of:
                //  - a cert file
                //  - cert data
                //  - insecure-skip-tls-verify
                let has_cd = cluster.conf.cert_data.is_some();
                match (&cluster.conf.cert, &cluster.conf.cert_data) {
                    (Some(cert_config_path), _) => {
                        if has_cd {
                            println!(
                                "Cluster {} specifies a certificate path and certificate data, \
                                 ignoring data and using the path",
                                cluster.name
                            );
                        }
                        let cert_path = get_full_path(cert_config_path.to_owned())?;
                        match File::open(cert_path) {
                            Ok(f) => {
                                let mut br = BufReader::new(f);
                                let mut s = String::new();
                                br.read_to_string(&mut s).expect("Couldn't read cert");
                                cluster_map.insert(
                                    cluster.name.clone(),
                                    ClusterConf::new(Some(s), cluster.conf.server.clone()),
                                );
                            }
                            Err(e) => {
                                println!(
                                    "Invalid server cert path for cluster {}: {}.\nAny contexts \
                                     using this cluster will be unavailable.",
                                    cluster.name, e
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
                                    e
                                ))
                            })?;
                            cluster_map.insert(
                                cluster.name.clone(),
                                ClusterConf::new(Some(cert_pem), cluster.conf.server.clone()),
                            );
                        }
                        Err(e) => {
                            println!("Invalid certificate data, could not base64 decode: {}", e);
                        }
                    },
                    (None, None) => {
                        let conf = if cluster.conf.skip_tls {
                            ClusterConf::new_insecure(None, cluster.conf.server.clone())
                        } else {
                            ClusterConf::new(None, cluster.conf.server.clone())
                        };
                        cluster_map.insert(cluster.name.clone(), conf);
                    }
                }
            }
        }

        // copy over contexts
        let mut context_map = HashMap::new();
        for iconf in iconfs.iter() {
            for context in iconf.contexts.iter() {
                context_map.insert(context.name.clone(), context.conf.clone());
            }
        }

        // copy over users
        let mut user_map = HashMap::new();
        for iconf in iconfs.iter() {
            for user in iconf.users.iter() {
                user_map.insert(user.name.clone(), user.conf.clone().into());
            }
        }

        let sources = match env::join_paths(paths.iter())?.into_string() {
            Ok(srcs) => srcs,
            Err(_) => "[config paths contain non-utf8 characters, cannot be displayed]".to_string(),
        };

        Ok(Config {
            source_file: sources,
            clusters: cluster_map,
            contexts: context_map,
            users: user_map,
        })
    }

    pub fn namespace_for_context(&self, context_name: &str) -> Result<Option<String>, KubeError> {
        let context = self
            .contexts
            .get(context_name)
            .ok_or(KubeError::Kube(KubeErrNo::InvalidContextName))?;
        Ok(context.namespace.clone())
    }

    pub fn cluster_for_context(
        &self,
        context_name: &str,
        click_conf: &ClickConfig,
    ) -> Result<Kluster, KubeError> {
        let context = self
            .contexts
            .get(context_name)
            .ok_or(KubeError::Kube(KubeErrNo::InvalidContextName))?;
        let cluster = self
            .clusters
            .get(&context.cluster)
            .ok_or(KubeError::Kube(KubeErrNo::InvalidCluster))?;
        let user = self
            .users
            .get(&context.user)
            .ok_or(KubeError::Kube(KubeErrNo::InvalidUser))?;

        let mut client_cert_key = None;
        let mut auth = None;
        for user_auth in user.auths.iter().rev() {
            match user_auth {
                UserAuth::Token(ref token) => auth = Some(KlusterAuth::with_token(token.as_str())),
                UserAuth::UserPass(ref username, ref password) => {
                    auth = Some(KlusterAuth::with_userpass(username, password))
                }
                UserAuth::AuthProvider(ref provider) => {
                    provider.copy_up();
                    auth = Some(KlusterAuth::with_auth_provider(*provider.clone()))
                }
                UserAuth::ExecProvider(ref provider) => {
                    auth = Some(KlusterAuth::with_exec_provider(provider.clone()))
                }
                UserAuth::KeyCertData(ref cert_data, ref key_data) => {
                    client_cert_key = Some(cert_key_from_data(cert_data, key_data, context_name))
                }
                UserAuth::KeyCertPath(ref cert_path, ref key_path) => {
                    client_cert_key = Some(cert_key_from_paths(
                        cert_path.clone(),
                        key_path.clone(),
                        context_name,
                    ))
                }
            };
        }

        // Turns the Option<Result> into a Result<Option>, then extracts the Option
        // or early returns if error
        let client_cert_key = client_cert_key.map_or(Ok(None), |r| r.map(Some))?;

        if auth.is_none() && client_cert_key.is_none() {
            println!(
                "[WARN]: Context {} has no client certificate and key, nor does it specify \
                 any auth method (user/pass, token, auth-provider).  You will likely not be \
                 able to authenticate to this cluster.  Please check your kube config.",
                context_name
            )
        }

        Kluster::new(
            context_name,
            cluster.cert.clone(),
            cluster.server.as_str(),
            auth,
            client_cert_key,
            cluster.insecure_skip_tls_verify,
            click_conf.connect_timeout_secs,
            click_conf.read_timeout_secs,
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;

    pub fn get_test_config() -> Config {
        Config {
            source_file: "/tmp/test.conf".to_string(),
            clusters: HashMap::new(),
            contexts: HashMap::new(),
            users: HashMap::new(),
        }
    }
}
