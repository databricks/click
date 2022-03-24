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

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::From;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};

//use crate::certs::{get_cert, get_cert_from_pem, get_key_from_str, get_private_key};
use super::kubefile::{AuthProvider, ExecProvider};
use crate::config::ClickConfig;
use crate::error::{ClickErrNo, ClickError};
use crate::k8s::UserAuth as K8SUserAuth;

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
    pub contexts: BTreeMap<String, super::kubefile::ContextConf>,
    pub users: HashMap<String, UserConf>,
}

// some utility functions
fn get_full_path(path: String) -> Result<String, ClickError> {
    if path.is_empty() {
        return Err(ClickError::ConfigFileError(
            "Empty certificate/key path".to_owned(),
        ));
    }
    // unwrap okay, validated above
    if path.starts_with('/') {
        Ok(path)
    } else if let Some(home_dir) = dirs::home_dir() {
        Ok(format!("{}/.kube/{}", home_dir.as_path().display(), path))
    } else {
        Err(ClickError::ConfigFileError(
            "Could not get path kubernetes \
             certificates/keys (not fully specified, and \
             your home directory is not known."
                .to_owned(),
        ))
    }
}

impl Config {
    pub fn from_files(paths: &[String]) -> Result<Config, ClickError> {
        let iconfs = paths
            .iter()
            .map(|config_path| super::kubefile::Config::from_file(config_path))
            .collect::<Result<Vec<_>, _>>()?;
        let sources = match env::join_paths(paths.iter())?.into_string() {
            Ok(srcs) => srcs,
            Err(_) => "[config paths contain non-utf8 characters, cannot be displayed]".to_string(),
        };
        Config::from_configs(iconfs, sources)
    }

    fn from_configs(
        iconfs: Vec<super::kubefile::Config>,
        source_file: String,
    ) -> Result<Config, ClickError> {
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
                                ClickError::ConfigFileError(format!(
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
        let mut context_map = BTreeMap::new();
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

        Ok(Config {
            source_file,
            clusters: cluster_map,
            contexts: context_map,
            users: user_map,
        })
    }

    pub fn get_context(
        &self,
        context_name: &str,
        click_conf: &ClickConfig,
    ) -> Result<crate::k8s::Context, ClickError> {
        let context = self
            .contexts
            .get(context_name)
            .ok_or(ClickError::Kube(ClickErrNo::InvalidContextName))?;
        let cluster = self
            .clusters
            .get(&context.cluster)
            .ok_or(ClickError::Kube(ClickErrNo::InvalidCluster))?;
        let user = self
            .users
            .get(&context.user)
            .ok_or(ClickError::Kube(ClickErrNo::InvalidUser))?;

        let endpoint = reqwest::Url::parse(&cluster.server)?;
        let ca_cert = match &cluster.cert {
            Some(cert) => {
                let reqwest_cert = get_reqwest_cert(cert)?;
                Some(reqwest_cert)
            }
            None => None,
        };

        let mut k8suser = Err(ClickError::ConfigFileError(
            "[WARN]: Context {} has no client certificate and key, nor does it specify \
             any auth method (user/pass, token, auth-provider).  You will likely not be \
             able to authenticate to this cluster.  Please check your kube config."
                .to_string(),
        ));
        //let mut auth = None;
        for user_auth in user.auths.iter().rev() {
            match user_auth {
                UserAuth::Token(token) => {
                    k8suser = K8SUserAuth::with_token(token.to_string());
                }
                UserAuth::UserPass(username, password) => {
                    k8suser =
                        K8SUserAuth::with_user_pass(username.to_string(), password.to_string());
                }
                UserAuth::AuthProvider(provider) => {
                    k8suser = K8SUserAuth::with_auth_provider(*provider.clone());
                }
                UserAuth::ExecProvider(provider) => {
                    k8suser = K8SUserAuth::with_exec_provider(provider.clone());
                }
                UserAuth::KeyCertData(cert_data, key_data) => {
                    k8suser = K8SUserAuth::from_key_cert_data(
                        key_data.clone(),
                        cert_data.clone(),
                        &endpoint,
                    );
                }
                UserAuth::KeyCertPath(cert_path, key_path) => {
                    let cert_full_path = get_full_path(cert_path.clone())?;
                    let key_full_path = get_full_path(key_path.clone())?;
                    k8suser =
                        K8SUserAuth::from_key_cert(&key_full_path, &cert_full_path, &endpoint);
                }
            };
        }

        k8suser.map(|user| {
            crate::k8s::Context::new(
                context_name,
                endpoint,
                ca_cert,
                Some(user),
                click_conf.connect_timeout_secs,
                click_conf.read_timeout_secs,
            )
        })
    }
}

fn get_reqwest_cert(data: &str) -> Result<reqwest::Certificate, ClickError> {
    reqwest::Certificate::from_pem(data.as_bytes()).map_err(|e| e.into())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::BTreeMap;

    pub fn get_test_config() -> Config {
        Config {
            source_file: "/tmp/test.conf".to_string(),
            clusters: HashMap::new(),
            contexts: BTreeMap::new(),
            users: HashMap::new(),
        }
    }

    fn get_config_from_kubefile_test_conf() -> Config {
        let kube_config = crate::config::kubefile::tests::get_parsed_test_config();
        Config::from_configs(vec![kube_config], "test".to_string()).unwrap() // ok, in test
    }

    #[test]
    fn ensure_valid_context() {
        let conf = get_config_from_kubefile_test_conf();
        let click_conf = crate::config::click::tests::get_parsed_test_click_config();
        assert!(conf.get_context("insecure_context", &click_conf).is_ok());
    }

    #[test]
    fn ensure_err_on_invalid_ca_cert() {
        let conf = get_config_from_kubefile_test_conf();
        let click_conf = crate::config::click::tests::get_parsed_test_click_config();
        assert!(conf.get_context("data_context", &click_conf).is_err()); // ca_cert is invalid
    }

    #[test]
    fn ensure_invalid_context() {
        let conf = get_config_from_kubefile_test_conf();
        let click_conf = crate::config::click::tests::get_parsed_test_click_config();
        assert!(conf.get_context("c1ctx", &click_conf).is_err()); // don't have certs
    }
}
