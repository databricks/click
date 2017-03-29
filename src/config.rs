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
use std::fs::File;

use kube::Kluster;
use error::{KubeError,KubeErrNo};

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
    #[serde(rename="certificate-authority")]
    pub cert: String,
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
    pub namespace: String,
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
    pub token: String,
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
            cluster_map.insert(cluster.name.clone(), cluster.conf.clone());
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
            clusters: cluster_map,
            contexts: context_map,
            users: user_map,
        }
    }

    pub fn cluster_for_context(&self, context: &str) -> Result<Kluster, KubeError> {
        self.contexts.get(context).map(|ctx| {
            self.clusters.get(&ctx.cluster).map(|cluster| {
                self.users.get(&ctx.user).map(|user| {
                    let cert_path = format!("/home/nick/.kube/{}",cluster.cert);
                    Kluster::new(context, cert_path.as_str(), cluster.server.as_str(), user.token.as_str())
                }).ok_or(KubeError::Kube(KubeErrNo::InvalidUser))
            }).ok_or(KubeError::Kube(KubeErrNo::InvalidCluster))
        }).ok_or(KubeError::Kube(KubeErrNo::InvalidContext)).
            and_then(|n| n).and_then(|n| n).and_then(|n| n)
    }
}
