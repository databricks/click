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

use std::convert::From;
use std::{env, error, fmt, io};

use serde_json::Value;

#[derive(Debug)]
pub enum ClickErrNo {
    InvalidContextName,
    InvalidCluster,
    InvalidUser,
    NoTokenAvailable,
    Unauthorized,
    Unknown,
}

static NO_TOKEN_STR: &str = "Couldn't get an authentication token from the auth-provider. \
                             You can try exiting Click and running a kubectl command \
                             against the cluster to refresh it.";

impl fmt::Display for ClickErrNo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClickErrNo::InvalidContextName => write!(f, "Invalid Context Name"),
            ClickErrNo::InvalidCluster => write!(f, "Invalid Cluster Name"),
            ClickErrNo::InvalidUser => write!(f, "Invalid User Name"),
            ClickErrNo::NoTokenAvailable => write!(f, "{}", NO_TOKEN_STR),
            ClickErrNo::Unauthorized => write!(
                f,
                "Not authorized to talk to cluster, check credentials in config"
            ),
            ClickErrNo::Unknown => write!(f, "Unknown error talking to cluster"),
        }
    }
}

impl error::Error for ClickErrNo {
    fn description(&self) -> &str {
        match self {
            ClickErrNo::InvalidContextName => "Invalid Context Name",
            ClickErrNo::InvalidCluster => "Invalid Cluster Name",
            ClickErrNo::InvalidUser => "Invalid User Name",
            ClickErrNo::NoTokenAvailable => NO_TOKEN_STR,
            ClickErrNo::Unauthorized => {
                "Not authorized to talk to cluster, check credentials in config"
            }
            ClickErrNo::Unknown => "Unknown error talking to cluster",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

#[derive(Debug)]
pub enum ClickError {
    CommandError(String),
    ParseErr(String),
    Kube(ClickErrNo),
    ConfigFileError(String),
    DecodeError(base64::DecodeError),
    Io(io::Error),
    SerdeJson(serde_json::Error),
    SerdeYaml(serde_yaml::Error),
    RequestError(k8s_openapi::RequestError),
    ResponseError(k8s_openapi::ResponseError),
    Clap(clap::Error),
    JoinPathsError(env::JoinPathsError),
    Pem(pem::PemError),
    Reqwest(reqwest::Error, Option<Value>),
    UrlParse(url::ParseError),
}

impl fmt::Display for ClickError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClickError::CommandError(ref s) => write!(f, "Error running command: {}", s),
            ClickError::ParseErr(ref s) => write!(f, "Parse Error: {}", s),
            ClickError::Kube(ref err) => write!(f, "Kube Error: {}", err),
            ClickError::ConfigFileError(ref s) => write!(f, "Failed to get config: {}", s),
            ClickError::DecodeError(ref err) => write!(f, "Base64 decode error: {}", err),
            ClickError::Io(ref err) => write!(f, "IO error: {}", err),
            ClickError::SerdeJson(ref err) => write!(f, "Serde json error: {}", err),
            ClickError::SerdeYaml(ref err) => write!(f, "Serde yaml error: {}", err),
            ClickError::RequestError(ref err) => match err {
                k8s_openapi::RequestError::Http(e) => {
                    write!(f, "Error preparing HTTP request: {}", e)
                }
                k8s_openapi::RequestError::Json(e) => write!(
                    f,
                    "Error serializing the JSON body of the HTTP request: {}",
                    e
                ),
            },
            ClickError::ResponseError(ref err) => match err {
                k8s_openapi::ResponseError::NeedMoreData => {
                    write!(f, "Failed to read enough data")
                }
                k8s_openapi::ResponseError::Json(e) => {
                    write!(f, "Failed to deserialize response json: {}", e)
                }
                k8s_openapi::ResponseError::Utf8(e) => {
                    write!(f, "Response contained invalid utf-8 data: {}", e)
                }
            },
            ClickError::Clap(ref err) => write!(f, "Error in clap: {}", err),
            ClickError::JoinPathsError(ref err) => write!(f, "Join paths error: {}", err),
            ClickError::Pem(ref err) => write!(f, "Pem error: {}", err),
            ClickError::Reqwest(ref err, _) => write!(f, "Reqwest error: {}", err),
            ClickError::UrlParse(ref err) => write!(f, "Error parsing url: {}", err),
        }
    }
}

impl error::Error for ClickError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            ClickError::CommandError(_) => None,
            ClickError::ParseErr(_) => None,
            ClickError::Kube(ref err) => Some(err),
            ClickError::ConfigFileError(_) => None,
            ClickError::DecodeError(ref err) => Some(err),
            ClickError::Io(ref err) => Some(err),
            ClickError::SerdeJson(ref err) => Some(err),
            ClickError::SerdeYaml(ref err) => Some(err),
            ClickError::RequestError(ref err) => Some(err),
            ClickError::ResponseError(ref err) => Some(err),
            ClickError::Clap(ref err) => Some(err),
            ClickError::JoinPathsError(ref err) => Some(err),
            ClickError::Pem(ref err) => Some(err),
            ClickError::Reqwest(ref err, _) => Some(err),
            ClickError::UrlParse(ref err) => Some(err),
        }
    }
}

// TODO: Macro all below

impl From<io::Error> for ClickError {
    fn from(err: io::Error) -> ClickError {
        ClickError::Io(err)
    }
}

impl From<serde_json::Error> for ClickError {
    fn from(err: serde_json::Error) -> ClickError {
        ClickError::SerdeJson(err)
    }
}

impl From<serde_yaml::Error> for ClickError {
    fn from(err: serde_yaml::Error) -> ClickError {
        ClickError::SerdeYaml(err)
    }
}

impl From<base64::DecodeError> for ClickError {
    fn from(err: base64::DecodeError) -> ClickError {
        ClickError::DecodeError(err)
    }
}

impl From<k8s_openapi::RequestError> for ClickError {
    fn from(err: k8s_openapi::RequestError) -> ClickError {
        ClickError::RequestError(err)
    }
}

impl From<clap::Error> for ClickError {
    fn from(err: clap::Error) -> ClickError {
        ClickError::Clap(err)
    }
}

impl From<env::JoinPathsError> for ClickError {
    fn from(err: env::JoinPathsError) -> ClickError {
        ClickError::JoinPathsError(err)
    }
}

impl From<pem::PemError> for ClickError {
    fn from(err: pem::PemError) -> ClickError {
        ClickError::Pem(err)
    }
}

impl From<reqwest::Error> for ClickError {
    fn from(err: reqwest::Error) -> ClickError {
        ClickError::Reqwest(err, None)
    }
}

impl From<url::ParseError> for ClickError {
    fn from(err: url::ParseError) -> ClickError {
        ClickError::UrlParse(err)
    }
}
