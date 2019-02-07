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
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read};

use error::{KubeErrNo, KubeError};
use kube::{Kluster, KlusterAuth};
use certs::{get_cert, get_cert_from_pem, get_key_from_str, get_private_key};

use super::kubefile::AuthProvider;

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

impl From<super::kubefile::UserConf> for UserConf {
    fn from(iconf: super::kubefile::UserConf) -> UserConf {
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
    if path.chars().next().unwrap() == '/' {
        Ok(path)
    } else if let Some(home_dir) = dirs::home_dir() {
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
    pub fn from_files(paths: &[String]) -> Result<Config, KubeError> {
        let iconfs = paths
            .into_iter()
            .map(|config_path| super::kubefile::Config::from_file(config_path))
            .collect::<Result<Vec<_>,_>>()?;

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
                                ClusterConf::new(Some(cert_pem), cluster.conf.server.clone()),
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

        let sources = match env::join_paths(paths.into_iter())?.into_string() {
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

