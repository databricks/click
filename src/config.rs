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
use std::io::{BufReader, Read};

use Env;
use error::{KubeError, KubeErrNo};
use kube::{Kluster, KlusterAuth};
use certs::{get_cert, get_cert_from_pem, get_private_key, get_key_from_str};

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
}


impl IConfig {
    fn from_file(path: &str) -> IConfig {
        let f = File::open(path).unwrap();
        serde_yaml::from_reader(f).unwrap()
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
fn auth_from_paths(
    client_cert_path: &String,
    key_path: &String,
    context: &str,
) -> Option<KlusterAuth> {
    if client_cert_path.len() == 0 {
        println!(
            "Empty client certificate path for {}, can't continue",
            context
        );
        return None;
    }
    if key_path.len() == 0 {
        println!("Empty client key path for {}, can't continue", context);
        return None;
    }

    let cert_full_path = if client_cert_path.chars().next().unwrap() == '/' {
        // unwrap is okay because we validated non-empty
        client_cert_path.clone()
    } else {
        format!(
            "{}/.kube/{}",
            env::home_dir().unwrap().as_path().display(),
            client_cert_path
        )
    };
    let key_full_path = if key_path.chars().next().unwrap() == '/' {
        key_path.clone()
    } else {
        format!(
            "{}/.kube/{}",
            env::home_dir().unwrap().as_path().display(),
            key_path
        )
    };
    if let (Some(cert), Some(private_key)) = (
        get_cert(cert_full_path.as_str()),
        get_private_key(key_full_path.as_str()),
    ) {
        Some(KlusterAuth::with_cert_and_key(cert, private_key))
    } else {
        println!("Can't read/convert cert or private key for {}", context);
        None
    }
}

fn auth_from_data(
    client_cert_data: &String,
    key_data: &String,
    context: &str,
) -> Result<Option<KlusterAuth>, KubeError> {
    if client_cert_data.len() == 0 {
        println!(
            "Empty client certificate data for {}, can't continue",
            context
        );
        return Ok(None);
    }
    if key_data.len() == 0 {
        println!("Empty client key data for {}, can't continue", context);
        return Ok(None);
    }
    let mut cert_enc = try!(::base64::decode(client_cert_data.as_str()));
    cert_enc.retain(|&i| i != 0);
    let cert = get_cert_from_pem(String::from_utf8(cert_enc).unwrap().as_str());
    let mut key_enc = try!(::base64::decode(key_data.as_str()));
    key_enc.retain(|&i| i != 0);
    let key = get_key_from_str(String::from_utf8(key_enc).unwrap().as_str());
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some(KlusterAuth::with_cert_and_key(c, k))),
        _ => Ok(None),
    }
}

impl Config {
    pub fn from_file(path: &str) -> Config {
        let iconf = IConfig::from_file(path);

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
                            "Cluster {} specifies a certificate path and certificate data, ignoring data and using the path",
                            cluster.name
                        );
                    }
                    let cert_path = if cert_config_path.chars().next().unwrap() == '/' {
                        cert_config_path
                    } else {
                        format!(
                            "{}/.kube/{}",
                            env::home_dir().unwrap().as_path().display(),
                            cert_config_path
                        )
                    };
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
                                "Invalid server cert path for cluster {}, cannot continue: {}",
                                cluster.name,
                                e.description()
                            );
                        }
                    }
                }
                (None, Some(cert_data)) => {
                    match ::base64::decode(cert_data.as_str()) {
                        Ok(mut cert) => {
                            cert.retain(|&i| i != 0);
                            cluster_map.insert(
                                cluster.name.clone(),
                                ClusterConf::new(
                                    Some(String::from_utf8(cert).unwrap()),
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
                    }
                }
                (None, None) => {
                    if cluster.conf.skip_tls.unwrap_or(false) {
                        println!(
                            "Can't do insecure-skip-tls-verify yet, ignoring cluster: {}",
                            cluster.name
                        );
                    //cluster_map.insert(cluster.name.clone(), ClusterConf::new(None,cluster.conf.server));
                    } else {
                        println!(
                            "Ignoring invalid cluster \"{}\": has no cert and tls verification not skipped",
                            cluster.name
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

        Config {
            source_file: path.to_owned(),
            clusters: cluster_map,
            contexts: context_map,
            users: user_map,
        }
    }

    pub fn cluster_for_context(&self, context: &str) -> Result<Kluster, KubeError> {
        self.contexts.get(context).map(|ctx| {
            self.clusters.get(&ctx.cluster).map(|cluster| {
                self.users.get(&ctx.user).map(|user| {

                    let auth =
                        if let Some(ref token) = user.token {
                            Some(KlusterAuth::with_token(token.as_str()))
                        } else if let (&Some(ref client_cert_path), &Some(ref key_path)) = (&user.client_cert, &user.client_key) {
                            auth_from_paths(client_cert_path, key_path, context)
                        } else if let (&Some(ref client_cert_data), &Some(ref key_data)) = (&user.client_cert_data, &user.client_key_data) {
                            try!(auth_from_data(client_cert_data, key_data, context))
                        } else {
                            println!("Invalid context {}.  Each user must have either a token or a client-certificate AND a client-key.", context);
                            None
                        };
                    match auth {
                        Some(a) => Kluster::new(context, cluster.cert.clone(), cluster.server.as_str(), a),
                        None => Err(KubeError::Kube(KubeErrNo::InvalidContext)),
                    }
                }).ok_or(KubeError::Kube(KubeErrNo::InvalidUser))
            }).ok_or(KubeError::Kube(KubeErrNo::InvalidCluster))
        }).ok_or(KubeError::Kube(KubeErrNo::InvalidContextName)).
            and_then(|n| n).and_then(|n| n).and_then(|n| n)
    }
}


/// Click config
#[derive(Debug, Deserialize, Serialize)]
pub struct ClickConfig {
    pub namespace: Option<String>,
    pub context: Option<String>,
}

impl ClickConfig {
    pub fn from_file(path: &str) -> ClickConfig {
        if let Ok(f) = File::open(path) {
            serde_yaml::from_reader(f).unwrap()
        } else {
            ClickConfig {
                namespace: None,
                context: None,
            }
        }
    }

    pub fn from_env(&mut self, env: &Env) {
        self.namespace = env.namespace.clone();
        self.context = env.kluster.as_ref().map(|k| k.name.clone());
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), KubeError> {
        let mut file = try!(File::create(path));
        try!(serde_yaml::to_writer(&mut file, &self));
        Ok(())
    }
}
