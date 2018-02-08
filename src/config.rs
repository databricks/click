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

use serde_yaml;

use std::collections::HashMap;
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
    #[serde(rename = "cluster")]
    conf: IClusterConf,
}

#[derive(Debug, Deserialize)]
struct IClusterConf {
    #[serde(rename = "certificate-authority")]
    pub cert: Option<String>,
    #[serde(rename = "certificate-authority-data")]
    pub cert_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify")]
    pub skip_tls: Option<bool>,
    pub server: String,
}

#[derive(Debug)]
pub struct ClusterConf {
    pub cert: Option<String>,
    pub server: String,
}

impl ClusterConf {
    fn new(cert: Option<String>, server: String) -> ClusterConf {
        ClusterConf {
            cert: cert,
            server: server,
        }
    }
}

#[derive(Debug, Deserialize)]
struct IContext {
    name: String,
    #[serde(rename = "context")]
    conf: ContextConf,
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
    #[serde(rename = "user")]
    conf: UserConf,
}

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
}

impl IConfig {
    fn from_file(path: &str) -> Result<IConfig, io::Error> {
        let f = File::open(path)?;
        serde_yaml::from_reader(f).map_err(|e|
                                           io::Error::new(io::ErrorKind::Other,
                                                          format!("Couldn't read yaml: {}",
                                                                  e.description())))
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
        return Err(KubeError::ConfigFileError("Empty certificate/key path".to_owned()));
    }
    // unwrap okay, validated above
    if path.chars().next().unwrap() == '/' {
        Ok(path)
    } else if let Some(home_dir) = env::home_dir() {
        Ok(format!(
            "{}/.kube/{}",
            home_dir.as_path().display(),
            path
        ))
    } else {
        return Err(KubeError::ConfigFileError("Could not get path kubernetes \
                                               certificates/keys (not fully specified, and \
                                               your home directory is not known."
                                              .to_owned()));
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
        return Err(KubeError::ConfigFileError(
            format!("Empty client key path for {}, can't continue", context)));
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
            "Can't read/convert cert or private key for {}", context)))
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
            context)))
    }
    else if key_data.len() == 0 {
        Err(KubeError::ConfigFileError(format!(
            "Empty client key data for {}, can't continue", context)))
    } else {
        let mut cert_enc = ::base64::decode(client_cert_data.as_str())?;
        cert_enc.retain(|&i| i != 0);
        let cert_pem = String::from_utf8(cert_enc).
            map_err(|e|
                    KubeError::ConfigFileError(format!(
                        "Invalid utf8 data in certificate: {}", e.description())))?;
        let cert = get_cert_from_pem(cert_pem.as_str());
        let mut key_enc = ::base64::decode(key_data.as_str())?;
        key_enc.retain(|&i| i != 0);
        let key_str = String::from_utf8(key_enc).
            map_err(|e|
                    KubeError::ConfigFileError(format!(
                        "Invalid utf8 data in key: {}", e.description())))?;
        let key = get_key_from_str(key_str.as_str());
        match (cert, key) {
            (Some(c), Some(k)) => Ok(KlusterAuth::with_cert_and_key(c, k)),
            _ => Err(KubeError::ConfigFileError(format!(
                "Invalid certificate or key data for context: {}", context)))
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
                        let cert_pem = String::from_utf8(cert).
                            map_err(|e|
                                    KubeError::ConfigFileError(format!(
                                        "Invalid utf8 data in certificate: {}", e.description())))?;
                        cluster_map.insert(
                            cluster.name.clone(),
                            ClusterConf::new(
                                Some(cert_pem),
                                cluster.conf.server,
                            ),
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
                    if cluster.conf.skip_tls.unwrap_or(false) {
                        println!(
                            "Can't do insecure-skip-tls-verify yet, ignoring cluster: {}",
                            cluster.name
                        );
                    //cluster_map.insert(cluster.name.clone(), ClusterConf::new(None,cluster.conf.server));
                    } else {
                        println!(
                            "Ignoring invalid cluster \"{}\": has no cert and tls verification not \
                             skipped", cluster.name
                        );
                    }
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
        for user in iconf.users.iter() {
            user_map.insert(user.name.clone(), user.conf.clone());
        }

        Ok(Config {
            source_file: path.to_owned(),
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
                                let auth = if let Some(ref token) = user.token {
                                    Ok(KlusterAuth::with_token(token.as_str()))
                                } else if let (&Some(ref username), &Some(ref password)) =
                                    (&user.username, &user.password)
                                {
                                    Ok(KlusterAuth::with_userpass(username, password))
                                } else if let (&Some(ref client_cert_path), &Some(ref key_path)) =
                                    (&user.client_cert, &user.client_key)
                                {
                                    auth_from_paths(client_cert_path.clone(),
                                                    key_path.clone(),
                                                    context)
                                } else if let (&Some(ref client_cert_data), &Some(ref key_data)) =
                                    (&user.client_cert_data, &user.client_key_data)
                                {
                                    auth_from_data(client_cert_data, key_data, context)
                                } else {
                                    Err(KubeError::ConfigFileError(format!(
                                        "Invalid context {}.  Each user must have either a token, \
                                         a username AND password, or a client-certificate AND \
                                         a client-key.", context)))
                                }?;
                                Kluster::new(
                                    context,
                                    cluster.cert.clone(),
                                    cluster.server.as_str(),
                                    auth
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
