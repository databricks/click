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

#[derive(Debug)]
pub enum KubeErrNo {
    InvalidContextName,
    InvalidCluster,
    InvalidUser,
    Unauthorized,
    Unknown,
}

impl fmt::Display for KubeErrNo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KubeErrNo::InvalidContextName => write!(f, "Invalid Context Name"),
            KubeErrNo::InvalidCluster => write!(f, "Invalid Cluster Name"),
            KubeErrNo::InvalidUser => write!(f, "Invalid User Name"),
            KubeErrNo::Unauthorized => write!(
                f,
                "Not authorized to talk to cluster, check credentials in config"
            ),
            KubeErrNo::Unknown => write!(f, "Unknown error talking to cluster"),
        }
    }
}

impl error::Error for KubeErrNo {
    fn description(&self) -> &str {
        match self {
            KubeErrNo::InvalidContextName => "Invalid Context Name",
            KubeErrNo::InvalidCluster => "Invalid Cluster Name",
            KubeErrNo::InvalidUser => "Invalid User Name",
            KubeErrNo::Unauthorized => {
                "Not authorized to talk to cluster, check credentials in config"
            }
            KubeErrNo::Unknown => "Unknown error talking to cluster",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

// TODO: This should really be called ClickError
#[derive(Debug)]
pub enum KubeError {
    CommandError(String),
    ParseErr(String),
    Kube(KubeErrNo),
    KubeServerError(String),
    ConfigFileError(String),
    DecodeError(base64::DecodeError),
    Io(io::Error),
    SerdeJson(serde_json::Error),
    SerdeYaml(serde_yaml::Error),
    RequestError(k8s_openapi::RequestError),
    Clap(clap::Error),
    JoinPathsError(env::JoinPathsError),
    Pem(pem::PemError),
    Reqwest(reqwest::Error),
}

impl fmt::Display for KubeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KubeError::CommandError(ref s) => write!(f, "Error running command: {}", s),
            KubeError::ParseErr(ref s) => write!(f, "Parse Error: {}", s),
            KubeError::Kube(ref err) => write!(f, "Kube Error: {}", err),
            KubeError::KubeServerError(ref s) => write!(f, "Server Error: {}", s),
            KubeError::ConfigFileError(ref s) => write!(f, "Failed to get config: {}", s),
            KubeError::DecodeError(ref err) => write!(f, "Base64 decode error: {}", err),
            KubeError::Io(ref err) => write!(f, "IO error: {}", err),
            KubeError::SerdeJson(ref err) => write!(f, "Serde json error: {}", err),
            KubeError::SerdeYaml(ref err) => write!(f, "Serde yaml error: {}", err),
            KubeError::RequestError(ref err) => match err {
                k8s_openapi::RequestError::Http(e) => {
                    write!(f, "Error preparing HTTP request: {}", e)
                }
                k8s_openapi::RequestError::Json(e) => write!(
                    f,
                    "Error serializing the JSON body of the HTTP request: {}",
                    e
                ),
            },
            KubeError::Clap(ref err) => write!(f, "Error in clap: {}", err),
            KubeError::JoinPathsError(ref err) => write!(f, "Join paths error: {}", err),
            KubeError::Pem(ref err) => write!(f, "Pem error: {}", err),
            KubeError::Reqwest(ref err) => write!(f, "Reqwest error: {}", err),
        }
    }
}

impl error::Error for KubeError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            KubeError::CommandError(_) => None,
            KubeError::ParseErr(_) => None,
            KubeError::Kube(ref err) => Some(err),
            KubeError::KubeServerError(_) => None,
            KubeError::ConfigFileError(_) => None,
            KubeError::DecodeError(ref err) => Some(err),
            KubeError::Io(ref err) => Some(err),
            KubeError::SerdeJson(ref err) => Some(err),
            KubeError::SerdeYaml(ref err) => Some(err),
            KubeError::RequestError(ref err) => Some(err),
            KubeError::Clap(ref err) => Some(err),
            KubeError::JoinPathsError(ref err) => Some(err),
            KubeError::Pem(ref err) => Some(err),
            KubeError::Reqwest(ref err) => Some(err),
        }
    }
}

impl From<io::Error> for KubeError {
    fn from(err: io::Error) -> KubeError {
        KubeError::Io(err)
    }
}

impl From<serde_json::Error> for KubeError {
    fn from(err: serde_json::Error) -> KubeError {
        KubeError::SerdeJson(err)
    }
}

impl From<serde_yaml::Error> for KubeError {
    fn from(err: serde_yaml::Error) -> KubeError {
        KubeError::SerdeYaml(err)
    }
}

impl From<base64::DecodeError> for KubeError {
    fn from(err: base64::DecodeError) -> KubeError {
        KubeError::DecodeError(err)
    }
}

impl From<k8s_openapi::RequestError> for KubeError {
    fn from(err: k8s_openapi::RequestError) -> KubeError {
        KubeError::RequestError(err)
    }
}

impl From<clap::Error> for KubeError {
    fn from(err: clap::Error) -> KubeError {
        KubeError::Clap(err)
    }
}

impl From<env::JoinPathsError> for KubeError {
    fn from(err: env::JoinPathsError) -> KubeError {
        KubeError::JoinPathsError(err)
    }
}

impl From<pem::PemError> for KubeError {
    fn from(err: pem::PemError) -> KubeError {
        KubeError::Pem(err)
    }
}

impl From<reqwest::Error> for KubeError {
    fn from(err: reqwest::Error) -> KubeError {
        KubeError::Reqwest(err)
    }
}
