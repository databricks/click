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
use std::env::{self};
use std::fs::File;

use ::Env;
use error::{KubeError,KubeErrNo};
use kube::{Kluster, KlusterAuth};
use certs::{get_cert, get_private_key};

fn empty_str() -> String {
    "".to_owned()
}

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
    #[serde(rename="cluster")]
    conf: ClusterConf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClusterConf {
    #[serde(rename="certificate-authority", default="empty_str")]
    pub cert: String,
    #[serde(rename="insecure-skip-tls-verify")]
    pub skip_tls: Option<bool>,
    pub server: String,
}

#[derive(Debug, Deserialize)]
struct IContext {
    name: String,
    #[serde(rename="context")]
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
    #[serde(rename="user")]
    conf: UserConf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserConf {
    pub token: Option<String>,
    #[serde(rename="client-certificate")]
    pub client_cert: Option<String>,
    #[serde(rename="client-key")]
    pub client_key: Option<String>
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

impl Config {
    pub fn from_file(path: &str) -> Config {
        let iconf = IConfig::from_file(path);

        // copy over clusters
        let mut cluster_map = HashMap::new();
        for cluster in iconf.clusters.iter() {
            if cluster.conf.cert != "" || cluster.conf.skip_tls.unwrap_or(false) {
                cluster_map.insert(cluster.name.clone(), cluster.conf.clone());
            } else {
                println!("Ignoring invalid cluster \"{}\": has no cert and tls verification not skipped", cluster.name);
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
                            KlusterAuth::with_token(token.as_str())
                        } else if let (&Some(ref client_cert_path), &Some(ref key_path)) = (&user.client_cert, &user.client_key) {
                            if let (Some(cert), Some(private_key)) = (get_cert(client_cert_path), get_private_key(key_path)) {
                                KlusterAuth::with_cert_and_key(cert, private_key)
                            } else {
                                panic!("Can't read/convert cert or private key");
                            }
                        } else {
                            panic!("Invalid kubeconfig!  Each user must have either a token or a client-certificate AND a client-key.");
                        };
                    let cert_opt =
                        if cluster.cert == "" {
                            None
                        } else {
                            if cluster.cert.chars().next().unwrap() == '/' {
                                Some(cluster.cert.clone())
                            } else {
                                Some(format!("{}/.kube/{}", env::home_dir().unwrap().as_path().display(), cluster.cert))
                            }
                        };
                    Kluster::new(context, cert_opt, cluster.server.as_str(), auth)
                }).ok_or(KubeError::Kube(KubeErrNo::InvalidUser))
            }).ok_or(KubeError::Kube(KubeErrNo::InvalidCluster))
        }).ok_or(KubeError::Kube(KubeErrNo::InvalidContext)).
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
