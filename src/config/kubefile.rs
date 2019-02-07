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

//! Code to handle reading and representing .kube/config files.  The code here is mostly just
//! deserialization, and conversion to the actual structs used elsewhere in code

use chrono::{DateTime, Local, TimeZone};
use chrono::offset::Utc;
use duct::cmd;
use serde_json::{self, Value};
use serde_yaml;

use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io;

//use error::{KubeErrNo, KubeError};
//use kube::{Kluster, KlusterAuth};
//use certs::{get_cert, get_cert_from_pem, get_key_from_str, get_private_key};


/// Kubernetes cluster config
#[derive(Debug, Deserialize)]
pub struct Config {
    pub clusters: Vec<Cluster>,
    pub contexts: Vec<Context>,
    pub users: Vec<User>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Config, io::Error> {
        let f = File::open(path)?;
        serde_yaml::from_reader(f).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Couldn't read yaml in '{}': {}", path, e.description()),
            )
        })
    }
}


#[derive(Debug, Deserialize)]
pub struct Cluster {
    pub name: String,
    #[serde(rename = "cluster")] pub conf: ClusterConf,
}

#[derive(Debug, Deserialize)]
pub struct ClusterConf {
    #[serde(rename = "certificate-authority")] pub cert: Option<String>,
    #[serde(rename = "certificate-authority-data")] pub cert_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify")] pub skip_tls: Option<bool>,
    pub server: String,
}

#[derive(Debug, Deserialize)]
pub struct Context {
    pub name: String,
    #[serde(rename = "context")] pub conf: ContextConf,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub name: String,
    #[serde(rename = "user")] pub conf: UserConf,
}


/// This represents what we can find in a user in the actual config file (note the Deserialize).
/// Hence all the optional fields.  At some point we should write a custom deserializer for this to
/// make it cleaner
#[derive(Debug, Deserialize, Clone)]
pub struct UserConf {
    pub token: Option<String>,

    #[serde(rename = "client-certificate")] pub client_cert: Option<String>,
    #[serde(rename = "client-key")] pub client_key: Option<String>,
    #[serde(rename = "client-certificate-data")] pub client_cert_data: Option<String>,
    #[serde(rename = "client-key-data")] pub client_key_data: Option<String>,

    pub username: Option<String>,
    pub password: Option<String>,

    #[serde(rename = "auth-provider")] pub auth_provider: Option<AuthProvider>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContextConf {
    pub cluster: String,
    //#[serde(default = "default")]
    pub namespace: Option<String>,
    pub user: String,
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
    pub fn copy_up(&self) {
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
