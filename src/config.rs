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
struct ClusterConf {
    #[serde(rename="certificate-authority")]
    cert: String,
    server: String,
}

#[derive(Debug, Deserialize)]
struct IContext {
    name: String,
    #[serde(rename="context")]
    conf: ContextConf,
}

#[derive(Debug, Deserialize, Clone)]
struct ContextConf {
    cluster: String,
    //#[serde(default = "default")]
    namespace: String,
    user: String,
}

#[derive(Debug, Deserialize)]
struct IUser {
    name: String,
    #[serde(rename="user")]
    conf: UserConf,
}

#[derive(Debug, Deserialize, Clone)]
struct UserConf {
    token: String,
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
    clusters: HashMap<String, ClusterConf>,
    contexts: HashMap<String, ContextConf>,
    users: HashMap<String, UserConf>,
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
}
